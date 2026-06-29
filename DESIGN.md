# Design

## Source of truth
- Status: Draft
- Last refreshed: 2026-06-29
- Primary product surfaces: Web vault app with login, encrypted record management, and encrypted cloud sync
- Evidence reviewed: Empty repository root, no existing UI or design docs

## Brand
- Personality: Calm, disciplined, secure, premium
- Trust signals: Explicit zero-knowledge framing, local decryption boundary, visible sync status, clear security labels
- Avoid: Cute banking, generic SaaS gradients, hidden states, vague security claims, dark-only UI

## Product goals
- Goals: Let users store, categorize, search, update, and delete sensitive account records while keeping cloud data encrypted
- Non-goals: Shared team vaults, autofill browser extension, password breach monitoring, secret sharing, enterprise admin controls
- Success signals: Users can log in, unlock locally, create records, sync encrypted vaults, and export/import backups without exposing plaintext to the server

## Personas and jobs
- Primary personas: Individual users managing many personal and work credentials
- User jobs: Save credentials, organize them by category, recover them on a trusted device, keep cloud copies encrypted
- Key contexts of use: Desktop browser, laptop browser, cloud-hosted deployment, occasional offline review

## Information architecture
- Primary navigation: Vault, Categories, Sync, Backup, Security
- Core routes/screens: Landing, auth, vault dashboard, record editor, security settings, backup/export
- Content hierarchy: Security status first, then collection overview, then searchable list, then record detail

## Design principles
- Principle 1: The app should make the security boundary obvious at every step
- Principle 2: Reduce cognitive load with one clear primary action per screen
- Tradeoffs: Favor local decryption and encrypted sync over server-side convenience features

## Visual language
- Color: Warm neutral base with deep ink, muted gold accents, and high-contrast status colors
- Typography: Editorial serif for headings, crisp sans for body and data
- Spacing/layout rhythm: Spacious 8px rhythm with strong section separation and card grouping
- Shape/radius/elevation: Rounded but restrained cards, light borders, subtle layered shadows
- Motion: Short easing on reveal, hover lift, and dialog transitions; avoid constant motion
- Imagery/iconography: Minimal line icons and geometric symbols, no illustrative clutter

## Components
- Existing components to reuse: None
- New/changed components: Hero status rail, vault list, record editor drawer, category chips, sync panel, backup card
- Variants and states: Empty, locked, unlocking, synced, dirty, error, offline
- Token/component ownership: CSS custom properties own color and spacing tokens; JS owns encryption and vault state

## Accessibility
- Target standard: WCAG 2.2 AA
- Keyboard/focus behavior: Full keyboard navigation, visible focus rings, logical tab order, escape-to-close dialogs
- Contrast/readability: High contrast body text, avoid low-contrast muted labels for critical information
- Screen-reader semantics: Form labels, live regions for sync state, accessible buttons and dialogs
- Reduced motion and sensory considerations: Honor reduced-motion preference and keep transitions short

## Responsive behavior
- Supported breakpoints/devices: Mobile, tablet, desktop
- Layout adaptations: Single-column stack on mobile, split-pane layout on wide screens
- Touch/hover differences: Larger tap targets and no hover-dependent critical actions

## Interaction states
- Loading: Skeleton-like status message and disabled primary actions
- Empty: Encouraging first-run vault prompt with a clear create-record action
- Error: Inline error callouts with recovery guidance
- Success: Confirmations for sync, save, copy, and export
- Disabled: Explicitly disabled while locked or unauthenticated
- Offline/slow network, if applicable: Queue local edits and surface pending sync state

## Content voice
- Tone: Direct, calm, and specific
- Terminology: Use vault, record, category, sync, unlock, backup, and local decryption consistently
- Microcopy rules: State who can read the data, what is stored, and what action is required next

## Implementation constraints
- Framework/styling system: Vanilla browser app with HTML, CSS, and ES modules
- Design-token constraints: CSS variables only for core theme tokens; avoid ad hoc color literals
- Performance constraints: No heavy runtime dependencies, keep first load fast, avoid unnecessary re-renders
- Compatibility constraints: Modern evergreen browsers with Web Crypto support
- Test/screenshot expectations: Verify login, vault unlock, CRUD, export, and sync flows in-browser

## Open questions
- [ ] Should cloud login and vault unlock use the same secret or remain separate?
- [ ] Should the first production version support multi-device unlock, or bind a vault to one trusted device?
- [ ] Which cloud storage target should the first deployed backend use: managed SQL, object storage, or document store?
