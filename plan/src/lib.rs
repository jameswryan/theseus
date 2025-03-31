// Copyright 2024 James Ryan

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use itertools::Itertools;
use tracing::error;

pub trait PlanItem<Journal: ?Sized>: Clone {
    type Error: core::error::Error;

    /// Forward execution of a plan item
    ///
    /// Execution *must* be atomic. If successful, it must return `Ok(())`.
    /// The optional second argument can be used to save state to the filesystem.
    fn execute(&self, journal: Option<&Journal>) -> Result<(), Self::Error>;

    /// Undo execution of an item
    ///
    /// This function must not fail
    fn unwind(&self, journal: Option<&Journal>);

    /// Provide a user-visible identification of the plan item
    fn identify(&self) -> String;
}

pub trait HasDeps<J: ?Sized, DJ: ?Sized>: PlanItem<J> {
    type Dep: PlanItem<DJ>;

    /// Get an iterator over the dependencies of this plan item.
    ///
    /// Dependencies of a plan item are properties of the ambient universe that
    /// **must** hold for item execution to succeed.
    fn dependencies(&self) -> impl IntoIterator<Item = Self::Dep>;
}

pub trait Plan<J: ?Sized, Item: PlanItem<J>>:
    IntoIterator<Item = Item> + Clone + Default
{
    /// Executes a plan.
    ///
    /// If execution of *all* items completes successfully, then the return
    /// value is `Ok(())`.
    /// If execution of an item fails, then the items that *were* completed are
    /// unwound, and the return value is `Err(<failed item>)`.
    fn execute_plan(self, journal: Option<&J>) -> Result<(), Item> {
        /* Peek lets us check if we complete the plan */
        let mut plan = self.into_iter().peekable();
        let completed: Vec<_> = plan
            .by_ref()
            .peeking_take_while(|p| {
                p.execute(journal).map_err(|e| error!("{}", e)).is_ok()
            })
            .collect();

        if plan.peek().is_none() {
            return Ok(());
        }

        completed.iter().for_each(|p| p.unwind(journal));
        /* Guaranteed to be Some(_) since something is left in plan */
        Err(plan.next().unwrap())
    }
}

impl<J: ?Sized, IT: PlanItem<J>, P> Plan<J, IT> for P where
    P: IntoIterator<Item = IT> + Clone + Default
{
}

pub trait DependentPlan<
    DJ: ?Sized,
    J: ?Sized,
    D: PlanItem<DJ>,
    DP: Plan<DJ, D>,
    IT: PlanItem<J> + HasDeps<J, DJ, Dep = D>,
>: Plan<J, IT>
{
    /// Execute the dependencies of this plan
    fn execute_dependencies(&self) -> Result<(), D> {
        self.dependencies().execute_plan(None)
    }

    /// Get an iterator over the dependencies of this plan
    ///
    /// Dependencies of a plan are the union of the dependencies of the items
    /// in the plan
    fn dependencies(&self) -> impl Plan<DJ, D>;
}

#[cfg(test)]
mod test {

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Foo {
        bar: u8,
    }

    #[derive(Debug)]
    struct FooError {}

    impl std::fmt::Display for FooError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "foo_error")
        }
    }

    impl std::error::Error for FooError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }

    impl PlanItem<()> for Foo {
        type Error = FooError;

        fn execute(&self, _: Option<&()>) -> Result<(), Self::Error> {
            if self.bar == 255 {
                return Err(FooError {});
            }
            Ok(())
        }

        fn unwind(&self, _: Option<&()>) {}

        fn identify(&self) -> String {
            format!("Foo {{ bar : {} }}", self.bar)
        }
    }

    fn a_passing_fooplan() -> Vec<Foo> {
        vec![Foo { bar: 1 }, Foo { bar: 2 }, Foo { bar: 3 }]
    }

    fn a_failing_fooplan() -> Vec<Foo> {
        vec![Foo { bar: 1 }, Foo { bar: 255 }, Foo { bar: 3 }]
    }

    #[test]
    fn passing_plan_passes() {
        assert!(a_passing_fooplan().execute_plan(None).is_ok())
    }

    #[test]
    fn failing_plan_fails_on_failing_item() {
        assert_eq!(
            a_failing_fooplan().execute_plan(None),
            Err(Foo { bar: 255 })
        )
    }
}
