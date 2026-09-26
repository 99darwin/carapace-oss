import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "test-results", "playwright-report"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-explicit-any": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Never inject HTML.",
        },
        {
          selector: "MemberExpression[property.name=/^(inner|outer)HTML$/]",
          message: "Never inject HTML.",
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Tokens stay in memory." },
        { name: "sessionStorage", message: "Tokens stay in memory." },
        { name: "indexedDB", message: "Tokens stay in memory." },
      ],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage" },
        { object: "window", property: "sessionStorage" },
        { object: "document", property: "cookie" },
      ],
    },
  },
  {
    files: ["*.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
