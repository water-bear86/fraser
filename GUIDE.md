# FRASER User Guide

The short version: make a wallet on an offline machine, fund it from
wherever your coins sit today, clean up after yourself, and know how to
get everything back out. This guide is just the steps. The deeper
why-and-how belongs to the docs section.

## 1. Set up air-gapped

1. On your everyday machine, get FRASER: **Code → Download ZIP** at
   [github.com/water-bear86/fraser](https://github.com/water-bear86/fraser),
   or `git clone`.
2. Copy the whole folder to a USB stick.
3. Move to the machine that will do the generating.
   - Best: a machine that is not online and never will be again. An old
     laptop with WiFi off, ideally running a live-booted Linux from USB,
     is perfect.
   - Acceptable: your own machine with WiFi and Bluetooth off and full
     disk encryption (FileVault or equivalent) on.
4. Connect a printer **with a cable**. Use a cheap home printer. Avoid
   office printers: many have hard drives that keep copies of every job.
5. Open `index.html` from the USB stick in a browser. The SYSTEM CHECK
   panel should show all OK, and the top bar should read `NET: ● OFFLINE`.

## 2. Generate and print

1. Keep **24 words** selected. Press `g`.
2. Press `p` and print the sheet.
3. Press `r` to reveal, then hand-copy the 24 words in pen onto the
   printout, checking each word. Ink fades; pen is the backup of the
   backup.
4. Verify the paper: press `v`, type the words **from the printout** into
   the verify box, and derive. All three addresses must match the sheet
   exactly. If anything differs, destroy the sheet and start over.
5. Make your extra copies now, while you are still offline (see best
   practices below).
6. Press `c` to clear, then quit the browser completely, not just the tab.

## 3. Clean up afterwards

The page stores nothing, but the machine and printer around it can.

- **Quit the browser entirely.** Copies of the phrase can sit in the
  browser's process memory until the process exits.
- **Shut the machine down fully** rather than letting it sleep. Shutdown
  clears RAM; sleep and hibernate can write RAM to disk. With disk
  encryption on, anything that did touch disk is encrypted at rest.
- **Power-cycle the printer.** Home printers hold the last job in
  volatile memory; off and on clears it. If your printer has a job
  history or a hard drive, it was the wrong printer for this.
- If you printed from your own machine instead of a live-boot: the print
  spooler briefly wrote the job to disk, and disk encryption covers it.
  The fix for next time is a live-booted OS, not forensics on this one.
- **The address is not a secret.** No need to scrub it anywhere; keep it
  handy (see watch-only below). The 24 words are the only secret.

## 4. Move your tokens in

1. Back on your everyday machine or phone, open the exchange or hot
   wallet that currently holds the funds.
2. Send a **small test amount** first. Scan the QR straight off the
   paper so nothing is mistyped. SOL goes to the SOL address, ETH and
   EVM tokens to the `0x` address, BTC to the `bc1q` address.
3. Confirm it arrived by pasting the address into a public explorer
   (solscan.io, etherscan.io, mempool.space). Looking up an address
   reveals nothing secret.
4. Send the rest. A few chunks instead of one big send is fine.
5. The paper never goes online to receive. You can keep depositing to it
   for years.

EVM note: the same `0x` address exists on every EVM chain (mainnet,
Base, Arbitrum, and so on). Send on a chain you will remember; funds
parked on a forgotten L2 are a classic way to lose track of money.

## 5. Move your tokens out

The moment the phrase touches an online device, the wallet is no longer
cold. So the rule is simple: **restoring = retiring.**

1. Install a wallet app yourself, from the official source: Phantom
   (SOL), MetaMask or Rabby (ETH), Sparrow or Electrum (BTC).
2. Choose restore / import seed phrase and type the 24 words from the
   paper. The paths and account index are printed on the sheet; most
   apps find the standard paths on their own.
3. Move everything you intend to move.
4. Treat the wallet as spent. Anything headed back to cold storage goes
   to a **freshly generated** FRASER wallet, never back to this one.
5. Once the new wallet is funded and verified, destroy every copy of the
   old one.

There is no safe partial exit. All three chains hang off the same
words, so restoring the phrase in any app exposes all of them at once.
If you only want to spend part of the funds, restore, move what you
need, then send the remainder on every chain to a freshly generated
wallet in the same sitting.

## 6. Best practices

- **Dry-run the whole loop first.** Generate a throwaway wallet, send it
  $10, restore it, sweep it out. Trust the process because you have
  completed it once, not because a README said so.
- **24 words, always,** for real money.
- **Serious money, multiple copies.** Two or three, in different places:
  home safe, bank deposit box, a trusted person. No single fire, flood,
  or burglary should be able to reach every copy.
- **A lot of money deserves metal.** Paper burns; stamped or etched
  steel does not. Hand-stamping 24 words into a cheap steel plate takes
  an evening and outlives the house.
- **The phrase never goes digital.** No photos, no scans, no screenshots,
  no password managers, no notes apps, no cloud. Paper and metal only.
- **Keep the addresses somewhere convenient** as watch-only: a bookmark
  to the explorer pages or a watch-only wallet. Check the balance any
  time without touching the secret.
- **Label copies discreetly** with the date and account index, not with
  "LIFE SAVINGS, SEED PHRASE" in marker.
- **Audit yearly.** Still readable, still where you left them? If a copy
  looks degraded, verify it offline with the verify panel and reprint.
- **Split large holdings** across two or more separate wallets so one
  lost or compromised sheet cannot take everything.
- **Plan for inheritance.** One trusted person should know a copy exists
  and how to use it. Unrecoverable and uninheritable are the same word
  on different days.
