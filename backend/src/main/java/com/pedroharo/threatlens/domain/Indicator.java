package com.pedroharo.threatlens.domain;

// this guy literally defines the type of evidence we are using, all the types aredefined in the enum IndicatorType:wa

public record Indicator(String submitted, String normalized, IndicatorType type) {}
