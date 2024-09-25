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

use tracing::error;

pub trait PlanItem<Save: ?Sized>: Sized {
    type Error: std::error::Error;

    /// Forward execution of a plan item
    /// Execution *must* be atomic. If successful, it must return `Ok(Self)`.
    /// The contained `Self` may a copy of the item executed, or it may be an
    /// item that can be used to unwind the executed item. The optional second
    /// argument can be used to save state to the filesystem
    /// If the function fails, it must return None
    fn execute(self, save: Option<&Save>) -> Result<Self, Self::Error>;

    /// Undo execution of an item
    /// This function must not fail
    fn unwind(&self);

    /// Provide a user-visible identification of the plan item
    fn identify(&self) -> String;
}

pub trait HasDeps<S: ?Sized, DS: ?Sized>: PlanItem<S> + Sized {
    type Dep: PlanItem<DS> + Ord;

    /// Get an iterator over the dependencies of this plan item
    /// Dependencies of a plan item are properties of the world that *must*
    /// hold for item execution to succeed.
    fn dependencies(&self) -> impl IntoIterator<Item = Self::Dep>;
}

pub trait Plan<S: ?Sized, Item: PlanItem<S>>: IntoIterator<Item = Item> + Sized {
    /// Executes a plan
    /// If execution of *all* items completes successfully, then the return
    /// value is `Ok(())`
    /// If execution of an item fails, then the items that *were* completed are
    /// unwound, and the return value is `Err(<failed item>)`
    fn execute_plan(self, save: Option<&S>) -> Result<(), Item> {
        /* Peek lets us check if we complete the plan */
        let mut plan = self.into_iter().peekable();
        let completed: Vec<_> = plan
            .by_ref()
            .map_while(|p| p.execute(save).map_err(|e| error!("{}", e)).ok())
            .collect();

        if plan.peek().is_none() {
            return Ok(());
        }

        completed.iter().for_each(|p| p.unwind());
        Err(plan.next().unwrap())
    }
}

impl<S: ?Sized, IT: PlanItem<S>, P> Plan<S, IT> for P where P: IntoIterator<Item = IT> {}

pub trait DependentPlan<
    DS: ?Sized,
    S: ?Sized,
    D: PlanItem<DS>,
    DP: IntoIterator<Item = D>,
    Item: PlanItem<S> + HasDeps<S, DS, Dep = D>,
>: IntoIterator<Item = Item> + Sized where
    DP: Plan<DS, D>,
{
    /// Execute the dependencies of this plan
    fn execute_dependencies(&self) -> Result<(), D> {
        let deps = self.dependencies().into_iter();
        deps.execute_plan(None)
    }

    /// Get an iterator over the dependencies of this plan
    /// Dependencies of a plan are the union of the dependencies of the items
    /// in the plan
    fn dependencies(&self) -> impl IntoIterator<Item = Item::Dep>;

    /// Print the dependencies of this plan
    fn print_deps(&self) {
        let deps = self.dependencies().into_iter();
        deps.for_each(|dep| println!("{}", dep.identify()))
    }
}
