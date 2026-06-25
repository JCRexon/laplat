-- Demo data for the local dev stack: one fictitious instructor and a handful of
-- published classes, so the catalog isn't empty while demoing. DEV ONLY.
-- Idempotent — safe to run on every `compose up` (ON CONFLICT DO NOTHING).
--
-- These bypass the normal instructor flow (which requires the verified tier +
-- can_instruct) by writing rows directly; they exist only to populate the
-- catalog for a walkthrough.

INSERT INTO users (id, handle, display_name, can_instruct)
VALUES ('demo-instructor-0001', 'demo_teacher', 'Demo Teacher', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO classes (id, instructor_id, title, description, status) VALUES
  ('demo-class-0001', 'demo-instructor-0001',
   'Conversational Vietnamese for Beginners',
   'Build everyday speaking confidence with live, friendly practice sessions.',
   'published'),
  ('demo-class-0002', 'demo-instructor-0001',
   'Introduction to Watercolour Painting',
   'Loosen up and learn colour, light and washes — no experience needed.',
   'published'),
  ('demo-class-0003', 'demo-instructor-0001',
   'Home Barista: Vietnamese Coffee Craft',
   'Master phin brewing, egg coffee and milk ratios from your own kitchen.',
   'published'),
  ('demo-class-0004', 'demo-instructor-0001',
   'Guitar Fundamentals: Your First Songs',
   'Chords, strumming and three full songs over a four-week live course.',
   'published'),
  ('demo-class-0005', 'demo-instructor-0001',
   'Yoga for Desk Workers',
   'Gentle mobility and posture resets you can do between meetings.',
   'published')
ON CONFLICT (id) DO NOTHING;
