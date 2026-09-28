# Original Bitcoin skin font fallback

WineTahoma-Regular.ttf and WineTahoma-Bold.ttf are Wine's unmodified,
freely redistributable Tahoma substitutes. Copyright (c) 2004 Larry Snyder,
based on Bitstream Vera Sans, copyright (c) 2003 Bitstream, Inc.
License: LGPL 2.1 or later; see LGPL-WineTahoma.txt.

Source (editable FontForge files):

- https://gitlab.winehq.org/wine/wine/-/blob/master/fonts/tahoma.sfd
- https://gitlab.winehq.org/wine/wine/-/blob/master/fonts/tahomabd.sfd

Only the original Bitcoin skin uses these fonts. It prefers genuine
installed Tahoma when available; the bundled substitutes make its compact
Windows typography available without a Wine or Microsoft font installation.
The caption prefers installed Trebuchet MS Bold, as Windows XP did, and
falls back to Tahoma Bold. No proprietary Microsoft font is bundled.
