package com.pedroharo.threatlens.domain;
// this is a cool feature of java, records are immutable and they generate some default methods at runtime by the compiler, this will generate getters and setters
// and methods for equals(), hashcode() and toString(), very cool, they are designed to be immutable data carriers, so this class is meant to only hold data, the data being the
// current shaped evidence that came from a normalized provider, see ProviderReport.java, each individual finding from the provider will become a evidenceItem object
public record EvidenceItem(
        String source, // which provider gave us this evidence
        EvidenceSeverity severity, // severity of the item, its enum named
        // you get the rest
        String category, 
        String title,
        String detail,
        String reference
) {}
