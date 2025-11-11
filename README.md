# Portfolio for Jake Dame

Follow the link to be taken to the GitHub repo for the corresponding project.

[reductor](https://github.com/jake-dame/Capstone) - Orchestral reduction generator

- Java, MIDI, MusicXML, ProxyMusic/JAXB
- Developed an extensible domain model for complex musical scores using composite structures and interval trees. Built robust import, adapter, validation, and export layers enabling accurate MIDI and MusicXML round-trip conversions
- Created a fluent, DSL-style API for constructing domain and format objects, streamlining testing of fragments
- Engineered music-reduction heuristics incorporating voice-leading and ergonomic constraints

[msd-script](https://github.com/jake-dame/msd-script) - A CLI + GUI scripting expression interpreter

- C++, CMake/Make, Qt
- Built an interpreter for a small mathematical expression language including variable binding, conditional evaluation, and function calls
- Leveraged Catch2 for testing, GitHub Actions for CI, and Make for build automation
- Added smart pointers and computation dictionary to optimize performance and ensure safe memory management
- Designed automated fuzz and corpus testing to harden reliability

[msd-paint](https://github.com/jake-dame/msd-paint) - A mobile drawing app for the Android platform

**With team**:

- Kotlin, Android Studio, JetPack Compose, JetPack Room, SQLite, H2, Google Firestore, Firebase
- Implemented an MVVM architecture with Jetpack Compose UI and Room ORM for seamless state and data persistence.
- Designed an intuitive gesture system using both touchscreen and gyroscope inputs to enhance creative interaction
- Integrated Firestore and Firebase for authentication, cloud storage, and social features (user feeds and saved drawings)

[skyrim-data-visualization](https://github.com/jake-dame/skyrim-data-visualization)

- JavaScript, HTML, CSS, D3.js
- Developed an interactive D3.js visualization that combines zoomable circle packing and dynamic bar charts to explore relationships among 3,000+ Skyrim characters by race, class, skill, and stats
- Implemented robust JSON parsing and data cleaning logic to normalize inconsistent character attributes and locations across the dataset