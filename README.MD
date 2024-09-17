
# Koffee - Java Bytecode Disassembler
![Java](https://img.shields.io/badge/Java-8%2B-brightgreen.svg) [![Build Status](https://ci.mdma.dev/api/badges/xBrownieCodezV2/koffee-disassembler/status.svg)](https://ci.mdma.dev/xBrownieCodezV2/koffee-disassembler)

Koffee is a lightweight and fast disassembler for Java bytecode. It allows developers to analyze `.class` files and inspect the bytecode in a human-readable format.

## Features

- Disassemble `.class` files to human-readable Java bytecode
- Supports Java 8 and above
- Lightweight with minimal dependencies
- Fast disassembly with accurate bytecode mapping
- Supports output customization

## Installation

### Prerequisites

- **Java 8 or higher** must be installed.
- **Maven** must be installed to build the project.

### Clone the Repository

```bash
git clone https://github.com/xBrownieCodezV2/koffee-disassembler.git
```
### Build the Project

To build the project using Maven, navigate to the project directory and run:

```bash
# Navigate into the project directory
cd koffee-disassembler

# Package the project with Maven
mvn package
```
This will compile the project and package it into a JAR file located in the `target/` directory.

### Maven Dependency

To use Koffee as a dependency in your Maven project, add the following to your `pom.xml`:

```xml
<dependency>
  <groupId>de.brownie</groupId>
  <artifactId>koffee</artifactId>
  <version>1.0.2</version>
</dependency>
```
### Maven Repository

Add the following repository to your `pom.xml` to resolve the dependency:

```xml
<repository>
  <id>qtechnologies</id>
  <url>https://nexus.mdma.dev/repository/maven-releases/</url>
</repository>
```
