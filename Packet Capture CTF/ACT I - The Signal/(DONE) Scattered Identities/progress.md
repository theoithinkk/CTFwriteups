Status: PARKED 2026-10-18 (blocked on 2 deleted Reddit images)

Chain so far:
1. Sheet owner via Drive API (key from the edit page): cloveeen@gmail.com, Gaia ID 110311086247787358658. Maps, calendar and avatar are all empty.
2. GitHub commit search by email: Clovendadoor/Find-me-turts
   - README: "Red is a bit odd and blue is a bit even"
   - Turts file: "2-7"
3. Reddit u/Clovendadoor (via Arctic Shift):
   - "Red" (body "Even"): i.redd.it/2k9oq0uj8rhh1.png (900x600). DELETED (404)
   - "Odd": i.redd.it/fdh9uxdd8rhh1.png (376x815). DELETED (404)
   - r/FindingMyTutles "We can ask him how much we need": Jason Voorhees, so 13, so ROT13
4. No Wayback copies of the images. Bluesky has no matching accounts.

5. Confirmed 2026-10-18: the user opened both posts while logged in, and Reddit says "file isn't available". The images are deleted server-side.

6. Archive metadata: the author deleted both images within ~36h of posting (Aug 7). The GitHub repo was made Sep 5.
7. Alternatives tried, all empty:
   - repo branches, tags, releases, issues, forks and diffs
   - Clovendadoor on ~20 other sites (X, Telegram, Bluesky, GitLab, Keybase, Mastodon, etc.)
   - red/blue bit planes of the GitHub avatar and the Jason JPEG
   - related subreddit names

8. Retried 2026-10-18 (session 2), all empty:
   - Sheet xlsx export: 1 visible sheet, no hidden sheets, defined names, comments, images or colored cells.
     Cells: Turtles/Tortoise/Shells, Oskejnend/Snapping tortoise/Sea shell, Tortoise/Tortoise/Clovers,
     Sea turtles/Clovers, A6 "Find the turtle", B10 "Packet", C11 "You need to look st me", C14 "Thisisadistraction".
   - "Oskejnend" is not a username (GitHub, Arctic Shift and Bluesky all return not found), and no Caesar shift turns it into a word.
   - Every preview.redd.it size (108-640 px plus source) and the thumbs.redditmedia copy of both images return 404.
   - Wayback CDX (retried once the archive was back online): 0 captures for i.redd.it and preview.redd.it of both image IDs,
     both post pages (www, old, and r/u_ paths), or the user profile.
   - archive.today: /newest returns 404 and the timemap has "no Mementos" for both images and the profile.
   => No public copy of the Red/Odd images exists anywhere we can reach.

9. Session 3 (2026-10-18), new brief wording: "think outside of the cell / the hole he left behind /
   see the identities linked to it without being named". All empty:
   - Drive metadata: modified 2026-10-18 03:57 UTC (version 879) by the owner, but the cells, styles and
     sheet list are unchanged. The xlsx now has drawing1.xml and persons.xml parts, but both are empty stubs.
     The live sheet shows no floating image or drawing.
   - lastModifyingUser = owner (cloveeen). No other identities in the Drive metadata.
   - Google account avatar (=s0, 720px) is the default silhouette.
   - Arctic Shift: no new posts or comments by Clovendadoor since Aug 6.
   - GitHub Clovendadoor: 0 following/stars/gists/events; both commits are by cloveeen@gmail.com.
     The 2 followers (PSergio984, CornyFranz) have real names, so they're likely real players. Not pursued.

10. Session 3, second angle (profile/object metadata), all empty:
   - r/FindingMyTutles subreddit metadata (Arctic Shift): description is boilerplate, and the
     public description is "Sub for finding my tutles". Banner, icon and mobile banner are Reddit stock presets.
     u_Clovendadoor profile sub: not archived.
   - Drive comments list: empty. Revisions and permissions need OAuth (owner only).
   - /edit page model: no hyperlinks, emails, notes or smart chips. D11:E11 and D14:E14 carry style s2 (borders only).
     The og:image thumbnail (lh7-us) renders only the same cells, so there's no floating image or drawing.
   - "Oskejnend": Vigenere (dec+enc), Beaufort, Atbash and all 26 Caesar shifts with ~28 keys (sheet words,
     usernames, jason/thirteen, red/blue/odd/even, packetcapture). Nothing readable.

9. Fresh attempt without the images (session 1, 2026-10-18), all empty:
   - the sheet was re-edited today (version 1128), but its contents are byte-identical to before
   - GitHub Clovendadoor: no social accounts, SSH/GPG keys, orgs or new commits. One follower (likely a player, not investigated).
   - r/FindingMyTutles banner/icon/mobile banner are Reddit's default templates (not stego carriers)
   - The user checked reddit.com/user/Clovendadoor: the ACCOUNT IS DELETED, which is why the Red/Odd media are gone.

10. More attempts (user asked to keep digging), all empty:
   - the sheet has no red/blue formatting (2 fonts, both black). ~75 cipher transforms on "Oskejnend" give nothing readable.
   - the GitHub follower PSergio984 is an unrelated active developer (dropped)
   - CDN variants (.jpg/.webp/.gif, format=png, external-preview, s3, i.reddituploads.com) all redirect to i.redd.it/removed.png
   - The Red/Odd posts were deleted individually (Aug 7); the Jason post is still live. Jason JPEG: R/G/B planes 0-7 and R/B interleaves are noise.

11. From-scratch pass (outside the cells), all empty:
   - Drive comments (incl. deleted): none. Revisions: need login; export ignores revision=.
   - editor-page bootstrap model: exactly the same 12 strings; no embedded objects, ranges, filters or metadata
   - GitHub avatar = WoW "Aspect of the Turtle" icon (116 TinEye hits, generic)

Next: ask the CTF organizers to re-upload the Red/Odd images (the challenge is broken without them).
Then: bit planes 2-7 (red=odd, blue=even?), then ROT13.

12. NEW HINT: "Every hint counts, except for the accounts that are removed or unmentioned"
   => the deleted Reddit account (Red/Odd/Jason) does NOT count; solve from the sheet + linked identities.
   Checked after the hint, all empty:
   - Oskejnend / cloveeen / clovendadoor: Instagram "Profile isn't available", TikTok "Couldn't find this account"
   - odd/even letter-shift brute force on "Oskejnend" (676 pairs) vs a 370k-word dictionary: no word
   - GitHub commit-email search for oskejnend@gmail/proton and clovendadoor@gmail: 0
   - Raider.io (WoW characters, since the avatar is a WoW icon): no Oskejnend/cloveeen/clovendadoor
   Open questions: what does "red odd / blue even / 2-7" apply to, if not the deleted images?

13. TEAMMATE LEAD: "blue" = X/Twitter. Account @NamoorKrommer, display name "IGotYourTurtles", joined Aug 2026, 0 posts,
   default avatar, no banner. Bio: "Do you know me? Did you find all of my 2 turtles? Their names are Namoor and Krommer"
   - No Wayback captures. GitHub/Reddit "Namoor" and "Krommer" are unrelated older real accounts (ignored).
   - "NamoorKrommer" = 13 letters (Jason = 13). ROT13 = AnzbbeXebzzre. Odd/even shifts and reversal give no dictionary words.
   - rosint.dev (a teammate's Reddit OSINT link) is behind Cloudflare for my browser.
   - Candidate flags to try (unlimited attempts): PacketCapture{Namoor_Krommer}, {NamoorKrommer}, {Namoor_and_Krommer}, {Krommer_Namoor}

14. Teammate tip: "a pivot leads to a YouTube channel; something in its description is used".
   Checked, none is the CTF channel:
   - @cloveeen (Joined Mar 9 2012, display name differs). The Gaia ID 1103... is ~2012-era, so it may be the same Google
     account, but it is EMPTY (no description, videos, playlists or posts).
   - Channel search by name: "Namoor" (@Tigers-c1z, 2024, Arabic), "Krommer" (@bobobobkins, 2012), "krommer" (2022, discord),
     @Namoor ("Namor", 2022): all pre-2026, unrelated.
   - @Krommer/@NamoorKrommer/@IGotYourTurtles/@Oskejnend/@Clovendadoor: 404. No channel matches by name for those.
   - Not yet possible: X forgot-password partial email (the teammate idea; must be done by the user, not me).
   - Teammate-supplied @BlueFlair: a real 2021 Roblox gaming channel (likely a minor). The description and 15 RSS video
     descriptions have nothing CTF-related, and nothing links it to the puzzle accounts. Treated as a wrong lead and NOT investigated further.
   - UPDATE: @BlueFlair came from a player who SOLVED it (not a teammate guess), so it is in the chain (maybe "blue").
     Channel UC22oNsNXEBuCId7qTAKXs3g, joined 2021-05-05, 166 subs, 47 videos.
     Description (no hidden chars): "I play roblox and don't forget to subscribe since u read this!\n\n\n100 Subs -March 29 2024"
     No puzzle terms in any of the ~209 strings on the channel pages. RSS shows only 15 videos, nearly all with empty descriptions.
     Wayback has no captures of @BlueFlair or its channel ID.
     Unknown: which challenge it belongs to, and how the solver pivoted to it.
