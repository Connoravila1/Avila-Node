    // Staged inside the existing ScriptPool impl, replacing worker() only.
    fn worker(&self) {
        loop {
            let jobs = {
                let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                while q.is_empty() {
                    q = self.avail.wait(q).unwrap_or_else(|e| e.into_inner());
                }
                let idle = self.experimental_workers
                    .saturating_sub(self.experimental_active.load(Ordering::Acquire)).max(1);
                let count = crate::experimental_advice::group_capacity()
                    .min(q.len().div_ceil(idle));
                self.experimental_active.fetch_add(1, Ordering::AcqRel);
                q.drain(..count).collect::<Vec<_>>()
            };
            let estimate = jobs.iter().map(|job| job.tx.inputs.len()).sum();
            let results = crate::experimental_advice::group(estimate, || {
                let results: Vec<_> = jobs.iter().map(|job| {
                    check_input_scripts(&job.tx, &job.outs, job.flags)
                }).collect();
                let error = results.iter().any(Result::is_err);
                (results, error)
            });
            // No block becomes checked until the whole group's pending
            // equations are verified or ordinary replay has replaced them.
            for (job, result) in jobs.iter().zip(results) {
                let mut guard = job.check.error.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(err) = result {
                    if guard.is_none() { *guard = Some(err); }
                }
                if job.check.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                    job.check.done.notify_all();
                }
            }
            self.experimental_active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Lab-only bridge for actual historical scripts with supplied prevouts.
    pub fn experimental_submit(&self, jobs: Vec<(Transaction, Vec<TxOut>, crate::script::ScriptFlags)>)
        -> std::sync::Arc<BlockCheck> {
        let check = std::sync::Arc::new(BlockCheck::new(jobs.len()));
        // Submit all at once to make the bounded group policy observable.
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for (tx, outs, flags) in jobs {
            q.push_back(ScriptJob { tx, outs, flags, check: std::sync::Arc::clone(&check) });
        }
        self.avail.notify_all();
        check
    }
