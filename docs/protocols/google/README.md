# Google APIs

Google `generateContent` and Interactions are modeled as separate protocol
surfaces. Native function arguments remain JSON objects where the source
requires objects; they are not stringified merely to match another provider's
wire representation.

The implementation phase must reverify which API is recommended at that time
and lock the official source revision before assertions are normative. No
stable Google pack is published yet.
