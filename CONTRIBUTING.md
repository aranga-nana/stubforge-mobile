# Contributing

Thanks for considering contributing!

## Quick Start
1. Fork & clone
2. `npm install`
3. Create a feature branch
4. Make changes + add tests/examples if relevant
5. Run lint / validation: `npm test` (if added) & `npm run validate:rules`
6. Open PR with clear description and rationale

## Pull Request Checklist
- Feature / fix clearly described
- README updated if user-facing change
- New rule examples placed under `stubs/` (if applicable)
- No committed key files (`keys/*.pem` ignored)
- No secrets or real tokens in examples

## Reporting Issues
Open an issue with:
- What you were doing
- Expected vs actual behavior
- Repro steps (curl or Postman)
- Relevant logs (trim sensitive data)

## Coding Guidelines
- Keep dependencies minimal
- Prefer small, composable functions
- Keep configuration JSON-driven

## Release Process (Maintainers)
1. Update CHANGELOG.md
2. Bump version in package.json
3. Tag: `git tag vX.Y.Z && git push --tags`
4. Draft GitHub Release (copy CHANGELOG section)

## Good First Issues
Look for the `good first issue` label. Add reproduction + acceptance criteria.

Happy hacking!
