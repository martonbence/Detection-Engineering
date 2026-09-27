// Runs BEFORE the Navigator code sliced out of scripts/docs/assets/page.js.
// That code was written for the rule browser and references a handful of its
// globals at call time; this page has no rule table, no rule drawer and no
// tabs, so each is stubbed to the "not applicable here" value. Keep this list
// in step with the identifiers the slice uses -- a missing one surfaces as a
// ReferenceError on the first click that reaches it, not at load.
var currentTab = 'navigator';     // Navigator keyboard handler gates on this
var RULE_IDX_BY_ID = {};          // no Rule Library rows to open
function openDrawer() { }          // ...so no rule drawer either
function closeDrawer() { }

// Same Escape-closes-the-legend listener page.js registers ahead of the
// Navigator's own key handler (registration order is what lets it
// stopImmediatePropagation before the detail panel also reacts).
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape' && typeof isInfoOpen === 'function' && isInfoOpen()) {
    e.stopImmediatePropagation();
    closeInfo();
  }
});
