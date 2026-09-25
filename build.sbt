import Dependencies._

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / crossScalaVersions := Seq("3.3.8", "3.9.0")

ThisBuild / scalacOptions := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  // "-Werror",
  "-java-output-version:25",
  "-Wvalue-discard",
  "-language:strictEquality",
  // "-Wnonunit-statement",
  "-Xcheck-macros",
  "-Xmax-inlines:64",
  "-Yfuture-lazy-vals",
  "-Ysafe-init"
)

lazy val root = (project in file("."))
  .settings(
    name := "openssl-practice-lab",
    libraryDependencies += munit % Test
  )

// Source: https://mvnrepository.com/artifact/org.pac4j/pac4j-oidc
libraryDependencies += "org.pac4j" % "pac4j-oidc" % "6.5.8" % "runtime"

// Source: https://mvnrepository.com/artifact/org.pac4j/pac4j-saml
// libraryDependencies += "org.pac4j" % "pac4j-saml" % "6.5.8" % "runtime"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bc-fips" % "2.1.3"
)

// Source: https://mvnrepository.com/artifact/software.amazon.awssdk/kms
libraryDependencies += "software.amazon.awssdk" % "kms" % "2.55.0"
