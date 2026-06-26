BEGIN;

ALTER TABLE app.projects DROP CONSTRAINT IF EXISTS projects_remix_of_id_fkey;
ALTER TABLE app.projects ADD CONSTRAINT projects_remix_of_id_fkey
    FOREIGN KEY (remix_of_id) REFERENCES app.projects(id) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE app.project_blobs DROP CONSTRAINT IF EXISTS project_blobs_project_id_fkey;
ALTER TABLE app.project_blobs ADD CONSTRAINT project_blobs_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES app.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE app.project_interactions DROP CONSTRAINT IF EXISTS project_interactions_project_id_fkey;
ALTER TABLE app.project_interactions ADD CONSTRAINT project_interactions_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES app.projects(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE app.messages DROP CONSTRAINT IF EXISTS messages_project_id_fkey;
ALTER TABLE app.messages ADD CONSTRAINT messages_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES app.projects(id) ON UPDATE CASCADE ON DELETE SET NULL;

COMMIT;
