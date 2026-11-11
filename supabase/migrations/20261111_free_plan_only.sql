-- One plan for now: the free trial ('free'). Every organisation moves to it, and no other plan name is accepted.
-- RUN THIS BEFORE deploying the code that creates organisations on 'free' (the old constraint rejects that name).
alter table organizations drop constraint if exists organizations_plan_check;
update organizations set plan = 'free' where plan <> 'free';
alter table organizations alter column plan set default 'free';
alter table organizations add constraint organizations_plan_check check (plan in ('free'));
