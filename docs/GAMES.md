# A thought experiment: keeping online games alive

> A philosophical side note, not a spec and not on the roadmap. It asks one question:
> could the structure behind Sympoden keep an online game world alive after the
> publisher switches off its servers, as long as enough players are still around?
> Nothing here is decided. It is written down so the thinking is not lost.

## The problem

Many games people *buy* only work while the publisher runs its servers. When the
servers go, the game goes, even in single-player modes. The money was spent for the
purpose of playing, yet the purchase does not survive the publisher's interest in it.
An offline option, or an end-of-life release, would at least leave something behind.

The question here is narrower and more technical: if the publisher released the rules
its servers follow, could the players themselves carry the world?

## The structure in ten principles

1. **Only your own contribution is controlled by you.** It is stored locally and with
   the players you actually played with, no one else. Same principle as Sympoden's
   ephemeral layer: each device stores mostly its owner's own data.
2. **The world is open.** Factions, markets, NPCs and places belong to everyone, and
   anyone can carry a copy. The more players, the more copies; like a torrent, the
   world lives as long as someone shares it.
3. **Places are entities with their own books.** An asteroid ring, a station, a
   faction: each has a ledger. What leaves one place enters another. Mine 50 tonnes
   and the ring has 50 tonnes less. This is double-entry bookkeeping, or a
   conservation law: nothing appears from nothing.
4. **History is append-only and signed.** Every entry carries the hash of the one
   before it. You can write, never change. A forged history shows the moment two
   copies meet, because they no longer match. (FOUNDATION §5: lock the record.)
5. **You only write your own actions.** "I mined 50 t here, signed, linked to the
   ring's latest state." The ring's side is not written by you; everyone computes it
   from the open rules. Writing an entry and being able to read and change the books
   are completely different things, and this structure only gives you the first.
6. **The rules set the ceiling.** Places deplete to zero and respawn on a schedule;
   ships mine only as fast as their gear allows. Any claim larger than what was
   *possible* can be rejected by anyone, without witnesses. Cheating can at best match
   perfect honest play, so it stops paying.
7. **Offline follows the same rules as online.** An offline mode is not a separate
   game, only the same simulation run locally with the same timetable: rings respawn,
   markets refill, the daily tick runs. Two players offline may each mine their own copy
   of the same ring; that is fine, because both copies are bounded by the rules.
   Online, the ring is shared and contested by gear, skill and timing, not split evenly.
8. **Growing is local, trading is shared.** You can grow potatoes alone on an island,
   but you do not know what they are worth until you reach the market. Production
   works offline; exchange needs the shared world. Goods sold offline are settled at
   the price when you come back, like a cheque cleared later. Of the options (fresh
   price snapshot or the shop is closed, volume caps, deferred settlement), deferred
   settlement is the least bad: going offline gives no gain, so there is nothing to
   exploit, and the trader carries the real-world risk that the price moved.
9. **Plausible lies are judged by trust.** What cannot be computed (a claim nobody
   else saw that stays within the rules and balances) falls back on Sympoden's
   approach to false information: witnesses who sign what they saw, track record, and
   weighting by the trust graph. A group of cheaters can agree among themselves, but
   they end up in their own version of the galaxy that nobody else's view takes into
   account. No ban needed; they cut themselves off.
10. **What remains of you is what you did, not who you were.** Delete your account and
    your own parts go: profile, logs, conversations. What you sent cannot be
    guaranteed deleted, and what you did in the open world stays, like a counted vote.
    A tag on a distant planet still reads *"First footfall: CMDR Jepson"*. That the
    commander is no longer among us is known only to those who flew with him.

## Three layers of defence against cheating

| Kind of cheat | Caught by | Needs trust? |
|---|---|---|
| Breaking the rules (a 200 ly jump in a 60 ly ship) | Arithmetic against the open rules | No |
| Goods from nothing, over-mining a place | Balance: every withdrawal must have its mirror, and claims on one place must add up | No |
| A consistent lie nobody else witnessed | Witnesses, track record, trust graph | Yes |

Structure does the work first; human judgement is kept for what cannot be computed.
That ordering is the same one Sympoden uses for facts.

## Is this a blockchain?

It uses the useful part of one: signed entries linked by hashes. It does not need the
expensive parts. There is no global consensus (only the players who were at a place
need to agree on its history, and a fixed tie-break rule orders concurrent entries the
same way a CRDT merge does), no full replication, and above all no token. When game
items become investments, players become workers and the game becomes a market. A
game world can also tolerate what a bank cannot: if two offline players over-draw a
ring, it simply refills more slowly.

## What is not solved

- **Small numbers.** "As long as there are enough players" is the real condition. A
  dying game has, almost by definition, fewer and fewer of them. Same frontier as
  Sympoden's discovery problem.
- **The rules belong to the publisher.** The server logic (tick, market model, respawn
  timers) would have to be released or licensed. Rebuilding it by reverse engineering
  usually breaks the EULA. Precedent exists for the clean route: community servers that
  later received an official licence.
- **Real-time play.** Combat between players still needs low-latency direct links; this
  sketch is about the persistent world, not the dogfight.
- **Who runs the first copy.** Bootstrapping a world without any server is the same
  cold-start problem as everywhere else in this project.

## Prior art

None of the pieces are new; the combination and the purpose are. Secure Scuttlebutt
(signed personal logs held by those who follow you), Holochain (agent-centric chains
validated against shared rules), Nostr (keys as identity), deterministic lockstep in
strategy games (send commands, everyone computes the same world), CRDTs and the
local-first movement, double-entry bookkeeping (Italy, 1400s), and the player-run data
networks that already exist around some games today.
