# Optional Sage threat rules

This directory is intentionally empty in the source package.

dsh-vigil does **not** bundle `@gendigital/sage-core` or its YAML rule set. Reasons,
recorded as a deliberate deviation from the original requirement draft (FR-2.2, §9):

1. **Licensing/attribution**: Sage rules are Apache-2.0 under DRL 1.1 obligations
   (retain author attribution, cite the source, credit the rule when a match is
   reported). Vendoring a drifting rule set into this package would put that
   upkeep on dsh-vigil.
2. **Supply-chain surface**: a security plugin whose job is to reduce install-time
   risk should not add native optional dependencies (`koffi`,
   `onnxruntime-node`) to every installation.
3. **Offline determinism**: the built-in rule set must work with no extra package
   and no network.

When you enable `sage.enabled` and point `sage.threatsDir` at a Sage rules
directory (or set `SAGE_THREATS_DIR`), the adapter loads the rules through Sage's
own `loadThreats()` and reports matches with attribution
("Sage (@gendigital/sage-core, Apache-2.0)").

If a future release vendors rules here, each bundled rule must keep its original
author attribution, cite its upstream source, and every matching verdict must
carry the rule id. Do not add rules here without that record.
