## Code Specter 👻

A simple, powerful browser bookmarklet to scan the client-side source code of any webpage for developer notes, comments, and potentially sensitive function patterns.

Features

  One-Click Scan: Analyze any webpage with a single click from your bookmarks bar.

  Finds Developer Notes: Searches for common developer annotations like TODO:, FIXME:, HACK:, and DEBUG.

  Identifies Function Patterns: Looks for string patterns of potentially risky functions that might be exposed in client-side code.

  Clean UI: Displays all findings in a clean, readable modal overlay with context snippets.

  Updatable: Use the loader method to automatically get the latest version of the script without ever updating your bookmark.

⚠️ Important Disclaimer

This bookmarklet operates only on the client-side. It can only analyze the HTML, JavaScript, and CSS that your browser has received from the server. It cannot see or analyze the actual server-side source code (e.g., the .php or .py files on the webserver).

Installation

You can install Code Specter in one of two ways. The Loader method is recommended for most users.

Method 1: Classic (Copy/Paste)

This method embeds the entire script into the bookmark. It's guaranteed to work on any site but requires you to manually update the bookmark if the code changes.

  Open the code-specter.js file in this repository and copy its entire contents.

  Right-click your bookmarks bar and select Add page... (Chrome) or New Bookmark... (Firefox).

  For Name, enter Code Specter.

  For URL (or Location), paste the full JavaScript code you copied.

  Save the bookmark.

Method 2: Loader (Recommended)

This method uses a tiny loader script in the bookmark that fetches the main script from GitHub. This means you'll always run the latest version.

Get the Raw File URL:

  Navigate to the code-specter.js file in your GitHub repository.

  Click the "Raw" button at the top right of the file view.

  Copy the URL from your browser's address bar. It should look something like https://raw.githubusercontent.com/CypherNova1337/Code-Specter/refs/heads/main/Code%20Specter.js.

Create the Bookmarklet:

  Right-click your bookmarks bar and select Add page... or New Bookmark....

  For Name, enter Code Specter.

  For URL, paste the loader code. Crucially, replace YOUR_RAW_URL_HERE with the actual raw URL you copied in step 1.

  Save the bookmark.

Security Note: This loader method may be blocked by some websites (like GitHub, Twitter, Facebook) that have a strict Content Security Policy (CSP). The classic method will still work on those sites.

How to Use

  Navigate to any webpage you want to analyze.

  Click the Code Specter bookmark.

  A modal window will appear, showing any found keywords and the context in which they appeared.

  Click the Close button to dismiss the window.

Keywords Searched

The script currently searches for the following strings (case-insensitive):

Developer Notes

    TODO:

    FIXME:

    NOTE:

    HACK:

    XXX:

    DEBUG

Potential Function Patterns

    PHP: eval(, assert(, system(, exec(, shell_exec(, passthru(, popen(, include(, require(, unserialize(, and backticks (`)

    Python: os.system(, pickle.loads(, yaml.load(

    JavaScript: document.write(, document.writeln(, innerHTML=

    Ruby: Marshal.load(
