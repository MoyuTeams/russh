use std::ptr::NonNull;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use super::{
    AdmissionScope, ErasedRooted, ErasedShared, FaultKind, ResourceClass, Rooted, ScopedFault,
};

struct Node<T> {
    value: Option<T>,
    next: Option<ErasedRooted<Node<T>>>,
}

struct State<T: Unpin> {
    head: Option<ErasedRooted<Node<T>>>,
    tail: Option<NonNull<Node<T>>>,
    waiter: Option<Waker>,
    closed: bool,
    senders: usize,
}

// tail 只指向 head 所拥有链条的最后节点，所有访问均持有同一 Mutex。
unsafe impl<T: Send + Unpin> Send for State<T> {}

impl<T: Unpin> State<T> {
    fn pop(&mut self) -> Option<ErasedRooted<Node<T>>> {
        let mut node = self.head.take()?;
        self.head = node.get_mut().next.take();
        if self.head.is_none() {
            self.tail = None;
        }
        Some(node)
    }
}

impl<T: Unpin> Drop for State<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

pub(crate) struct Sender<T: Unpin> {
    state: ErasedShared<Mutex<State<T>>>,
}
pub(crate) struct Receiver<T: Unpin> {
    state: ErasedShared<Mutex<State<T>>>,
}

impl<T: Unpin> std::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedReceiver")
    }
}

pub(crate) fn channel<T: Send + Unpin + 'static, S: AdmissionScope>(
    scope: &S,
    site: &'static str,
) -> Result<(Sender<T>, Receiver<T>), ScopedFault> {
    let state = Rooted::try_new(scope, ResourceClass::Control, site, || {
        Mutex::new(State {
            head: None,
            tail: None,
            waiter: None,
            closed: false,
            senders: 1,
        })
    })?
    .into_shared()
    .erase();
    let receiver = state.try_clone()?;
    Ok((Sender { state }, Receiver { state: receiver }))
}

impl<T: Send + Unpin + 'static> Sender<T> {
    pub(crate) fn try_clone(&self) -> Result<Self, ScopedFault> {
        let cloned = self.state.try_clone()?;
        let mut state = self
            .state
            .get()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.senders = state
            .senders
            .checked_add(1)
            .ok_or_else(|| ScopedFault::overflow("queue.senders"))?;
        Ok(Self { state: cloned })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state
            .get()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
    }

    pub(crate) fn close(&self) {
        let waiter = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    pub(crate) fn try_send<S: AdmissionScope>(
        &self,
        scope: &S,
        site: &'static str,
        value: T,
    ) -> Result<(), ScopedFault> {
        let mut node = Rooted::try_new(scope, ResourceClass::Runtime, site, || Node {
            value: Some(value),
            next: None,
        })?
        .erase();
        let waiter = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.closed {
                return Err(ScopedFault {
                    kind: FaultKind::Cancelled,
                    site,
                    requested: 0,
                    available: None,
                });
            }
            let tail = NonNull::from(node.get_mut());
            if let Some(mut old_tail) = state.tail {
                unsafe { old_tail.as_mut().next = Some(node) };
            } else {
                state.head = Some(node);
            }
            state.tail = Some(tail);
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        Ok(())
    }
}

impl<T: Unpin> Drop for Sender<T> {
    fn drop(&mut self) {
        let waiter = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.senders -= 1;
            if state.senders == 0 {
                state.waiter.take()
            } else {
                None
            }
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

impl<T: Send + Unpin + 'static> Receiver<T> {
    pub(crate) fn try_recv(&mut self) -> Option<T> {
        let node = self
            .state
            .get()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop();
        node.and_then(|mut node| node.get_mut().value.take())
    }
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let replacement = cx.waker().clone();
        let (node, closed, old) = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let node = state.pop();
            let closed = state.closed || state.senders == 0;
            let old = if node.is_some() || closed {
                Some(replacement)
            } else {
                state.waiter.replace(replacement)
            };
            (node, closed, old)
        };
        drop(old);
        match node {
            Some(mut node) => Poll::Ready(node.get_mut().value.take()),
            None if closed => Poll::Ready(None),
            None => Poll::Pending,
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<T> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub(crate) fn close(&mut self) {
        let old = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state.waiter.take()
        };
        drop(old);
    }
}

impl<T: Unpin> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (mut head, old) = {
            let mut state = self
                .state
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state.tail = None;
            (state.head.take(), state.waiter.take())
        };
        while let Some(mut node) = head {
            head = node.get_mut().next.take();
        }
        drop(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped::tests::{Scope, assert_no_allocations};

    #[test]
    #[allow(clippy::unwrap_used)]
    fn message_node_denial_precedes_every_allocator_call() {
        let scope = Scope::new(usize::MAX);
        let (sender, mut receiver) = channel::<u32, _>(&scope, "test.queue").unwrap();
        let held = scope.held();
        scope.freeze();
        assert_no_allocations(|| {
            assert_eq!(
                sender.try_send(&scope, "test.node", 42).unwrap_err().kind,
                FaultKind::ByteBudget
            );
        });
        assert!(receiver.try_recv().is_none());
        assert_eq!(scope.held(), held);
        drop(receiver);
        drop(sender);
        assert_eq!(scope.held(), 0);
    }
}
