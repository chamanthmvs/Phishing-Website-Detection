import next from "eslint-config-next";

// eslint-config-next 16 ships a native flat config (an array), so it can be
// spread directly without the legacy @eslint/eslintrc FlatCompat shim.
const eslintConfig = [
  ...next,
  {
    ignores: [".next/**", "node_modules/**"],
  },
];

export default eslintConfig;
