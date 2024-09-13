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

use std::path::Path;

pub trait PlanItem: Sized {
    /// Forward execution of a plan item
    /// Execution *must* be atomic. If successful, it must return `Some(Self)`.
    /// The contained `Self` may a copy of the item executed, or it may be an
    /// item that can be used to unwind the executed item. The optional second
    /// argument can be used to save state to the filesystem
    /// If the function fails, it must return None
    fn execute(self, save: &Path) -> Option<Self>;

    /// Undo execution of an item
    /// This function must not fail
    fn unwind(&self);

    /// Provide a user-visible identification of the plan item
    fn identify(&self) -> String;
}

pub trait Plan: Iterator<Item: PlanItem> + Sized {
    /// Executes a plan
    /// If execution of *all* items completes successfully, then the return
    /// value is `Ok(())`
    /// If execution of an item fails, then the items that *were* completed are
    /// unwound, and the return value is `Err(<failed item>)`
    fn execute_plan(self, save: &Path) -> Result<(), impl PlanItem> {
        /* Peek lets us check if we complete the plan */
        let mut plan = self.peekable();
        let completed: Vec<_> = plan.by_ref().map_while(|p| p.execute(save)).collect();

        if plan.peek().is_none() {
            return Ok(());
        }

        completed.iter().for_each(|p| p.unwind());
        Err(plan.next().unwrap())
    }
}

impl<IT: PlanItem, P> Plan for P where P: Iterator<Item = IT> {}
