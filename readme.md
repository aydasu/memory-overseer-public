I'm pretty bored switching github account every few months so I decided to stick with this one. It is looking pretty empty without public repos, but I still need to keep certain aspects of my private projects **private**. Well, here, this repo is basically a sanitized version of some kind of memory scanner tool / module I can actually share.

This is just a proof of concept showing how to scan Windwos process memory for byte patterns. Claude stripped out all the spesific patterns, offsets, and anything unrelated for an MRE. Just a quick scan from me and it's lgtm.

You get two python scripts. One for window to pid and another for pid to memory address. I've used this where finding a pointer is a lot headache.

This repository is created for decoration purposes for my profile. Don't randomly scan processes you don't have permission to analyze. Aka, don't play stupid games and never win stupid prizes! Legends say even Windows Notepad will have tamper protection in 2025.

> Memory is a canvas, don't ruin it.