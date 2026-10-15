import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resourceAndMembership, resourceIdFromRoute } from '../src/resource-zones.mjs';

const noteId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const resource = {
  resource_id: noteId, zone: 'class_announcement',
  class_id: 'class_a', title: 'virtual', content: 'virtual',
};
function database({ item = resource, member = null } = {}) {
  return {
    from(table) {
      const filters = [];
      return {
        select() { return this; },
        eq(field, value) { filters.push([field, value]); return this; },
        async maybeSingle() {
          const row = table === 'training_zone_resources' ? item
            : table === 'training_class_memberships' ? member : null;
          return { data: row && filters.every(([key, value]) => row[key] === value)
            ? row : null, error: null };
        },
      };
    },
  };
}
function itemPath(id = noteId, extra = {}) {
  return { url: '/api/class-announcements/' + id, query: { id }, ...extra };
}

test('서버 자원 ID는 단건 경로에 고정하며 쿼리 ID 바꿔치기를 거부한다', () => {
  assert.equal(resourceIdFromRoute(itemPath()), noteId);
  assert.throws(() => resourceIdFromRoute(itemPath(noteId,
    { query: { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' } })), 
  { status: 400, code: 'INVALID_RESOURCE_ID' });
  assert.throws(() => resourceIdFromRoute(itemPath('export')),
    { status: 400, code: 'INVALID_RESOURCE_ID' });
});
test('서버에서 실제 반 소속이 있는 사용자만 공지를 읽을 수 있다', async () => {
  const db = database({ member: { class_id: 'class_a', user_id: 'student_a', role: 'student' } });
  const { membership } = await resourceAndMembership(db, 'student_a', noteId, 'class_announcement');
  assert.equal(membership.role, 'student');
  await assert.rejects(resourceAndMembership(db, 'student_b', noteId, 'class_announcement'),
    { status: 404, code: 'RESOURCE_NOT_FOUND' });
});
test('다른 반 소속은 동일 사용자라도 해당 공지를 볼 수 없다', async () => {
  const db = database({ member: { class_id: 'class_b', user_id: 'student_a', role: 'instructor' } });
  await assert.rejects(resourceAndMembership(db, 'student_a', noteId, 'class_announcement'),
    { status: 404, code: 'RESOURCE_NOT_FOUND' });
});
test('공지 자원 구역이 다르면 DB 조회 결과를 공개하지 않는다', async () => {
  const db = database({ member: { class_id: 'class_a', user_id: 'student_a', role: 'student' } });
  await assert.rejects(resourceAndMembership(db, 'student_a', noteId, 'instructor_material'),
    { status: 404, code: 'RESOURCE_NOT_FOUND' });
});
test('서버에 저장된 강사 역할과 학생 역할은 구별된다', async () => {
  for (const role of ['student', 'instructor']) {
    const db = database({ member: { class_id: 'class_a', user_id: 'verified_user', role } });
    const { membership } = await resourceAndMembership(db, 'verified_user', noteId,
      'class_announcement');
    assert.equal(membership.role === 'instructor', role === 'instructor');
  }
});
