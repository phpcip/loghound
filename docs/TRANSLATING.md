# Translating Loghound

Every word Loghound shows — the panel, the login page, the installer, the messages the server
sends back — goes through one small translation layer. English is the source language and needs
no file at all. Every other language is a JSON file that maps the English text to its
translation.

Nothing about English changes when a translation is added, removed or broken: a string the
catalog does not have is shown in English, and a catalog that cannot be read is ignored.

## Choosing the language

- **Panel:** Settings → Display → Language, or `'language'` under `'ui'` in
  `config/loghound.php`. The value is a language code such as `ro`, `fr` or `pt-BR`.
- **Installer:** the language links at the top of every setup page. Before one is picked, the
  installer follows the browser's `Accept-Language` header. The choice is saved into the
  configuration it writes, so the panel opens in the same language.

CSV exports are always written in English, whatever the interface language is, so a file
exported from one installation can be imported into any other.

## Where catalogs live

| Location | Tracked in git | Purpose |
|---|---|---|
| `lang/<code>.json` | yes | The catalogs that ship with Loghound. |
| `config/lang/<code>.json` | no | Your own changes. Survive upgrades. |

Both files are read for the selected language, `lang/` first and `config/lang/` second, and a key
in the second replaces the same key in the first. So:

- **To change a few strings** of a shipped language, create `config/lang/<code>.json` holding only
  those keys. Everything else keeps coming from `lang/<code>.json`.
- **To add a language** Loghound does not ship, create `config/lang/<code>.json` from
  `lang/template.json`. It appears in the language list as soon as the file exists.

The language code is the file name. It must look like `xx`, `xxx`, `xx-YY` or `xx-Yyyy`
(for example `de`, `fil`, `pt-BR`, `zh-Hant`). Anything else is ignored.

## The file format

```json
{
    "@name": "Română",
    "@locale": "ro-RO",
    "Settings": "Setări",
    "Saved.": "Salvat.",
    "{n} of {total} sessions": "{n} din {total} sesiuni",
    "{n} sessions": {
        "one": "{n} sesiune",
        "few": "{n} sesiuni",
        "other": "{n} de sesiuni"
    }
}
```

- **`@name`** is what the language list shows. Write it in the language itself.
- **`@locale`** is optional. It goes into the page's `lang` attribute and decides the plural
  rules. When it is missing, the file name is used.
- **Every other key is the English text, exactly** — punctuation, capitals and spaces included.
  A key that does not match the English character for character is never used.
- **`{name}` placeholders** are filled in by Loghound: a number, a file name, a link, a piece of
  markup. Keep every one of them, spelled exactly the same. Move them wherever the sentence
  needs them.
- Values are **plain text**. HTML in a value is shown as text, not rendered; links and code
  inside a sentence arrive through placeholders.
- The file must be valid UTF-8 JSON, under 8 MB. A file that is not valid JSON is skipped and
  logged to the PHP error log.

### Plurals

A string that depends on a count appears in `lang/template.json` as an object keyed by its
English plural form, with English `one` and `other` forms:

```json
"{n} rules": { "one": "{n} rule", "other": "{n} rules" }
```

In a translation, give the forms your language uses, named by the
[CLDR plural categories](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html):
`zero`, `one`, `two`, `few`, `many`, `other`. `other` is always required; a category you leave
out falls back to `other`. Languages without plural forms, such as Chinese or Japanese, use a
plain string instead of an object.

## Keeping a catalog complete

`lang/template.json` holds every string Loghound can show, with English as the value. It is
generated from the source code:

```sh
php tools/i18n.php template        # rewrite lang/template.json
php tools/i18n.php check ro        # compare a catalog with the source
```

`check` lists the strings a catalog is missing, the strings it has that Loghound no longer uses,
and every translation that uses a placeholder the English text does not have. It exits with a
non-zero status when anything is missing or wrong, so it can run in CI.

After an upgrade, run `check` against your `config/lang/` file: new features bring new strings,
and those are shown in English until they are translated.

## For developers

Text shown to a person is never written as a bare string.

**PHP** (`Loghound\I18n`):

```php
I18n::t('Saved.');
I18n::t('Could not reach {host}.', ['host' => $host]);
I18n::tn('{n} rule', '{n} rules', $count);           // {n} is filled with $count
I18n::html('Read {doc} first.', ['doc' => '<code>docs/INSTALL.md</code>']);
I18n::mark('Checking the log directory');            // store English, translate when shown
```

- `t()` and `tn()` return plain text; escape it like any other text when it goes into HTML.
- `html()` and `htmln()` escape the translated sentence and then insert the parameters as
  markup. Only pass markup you built yourself, already escaped.
- `mark()` returns the English unchanged. Use it for text that is stored — in the database, in a
  job record, in a validation result — and translate it with `t()` where it is displayed, so a
  change of language also changes what was stored before.

**JavaScript** (`public/assets/js/i18n.js`):

```js
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from './i18n.js';

T('Saved.');
Tn('{n} rule', '{n} rules', count);
el('p', {}, Tf('Open {settings} to change it.', { settings: link }));   // DOM nodes as parameters
```

The module loads the catalog before any other module runs, so `T()` is safe at module level.

**Rules that keep the extractor working:**

- The first argument must be a literal string (or literal strings joined with `+`). A variable
  as the key is invisible to `tools/i18n.php`. When the text comes from a table, add the table
  to `REGISTRY` in `tools/i18n.php`.
- Put whole sentences in one key with placeholders. Do not glue translated fragments together:
  word order differs between languages.
- Never branch on translated text. Compare codes, flags or English values instead.
- Run `php tools/i18n.php template` after changing any user-facing text, and commit the new
  `lang/template.json` with the change.
