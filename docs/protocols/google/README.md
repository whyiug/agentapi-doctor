# Google APIs

Google `generateContent` and Interactions are modeled as separate protocol
surfaces. Native function arguments remain JSON objects where the source
requires objects; they are not stringified merely to match another provider's
wire representation.

Before implementing or promoting Google support, reverify the currently
recommended API and lock the official source revision before assertions become
normative. No stable Google pack is published yet.
