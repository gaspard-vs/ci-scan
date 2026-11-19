# Maven stage

OSV-Scanner checks the Maven packages of the `pom.xml` files. Most versions
are not in `pom.xml`: a parent or a BOM gives them, and these files are on
Maven Central. So the stage resolves the versions through a proxy.

```
runner ── copies of the pom.xml files ──▶ stage (OSV-Scanner)
                                              │ only network: "proxy"
                                              ▼
                                           helper ── GET *.pom ──▶ Maven Central
```

| Path | Content |
| --- | --- |
| `stage.json` | The stage. It uses the image of `../30-deps-osv`. |
| `helper/helper.py` | The proxy. Python standard library only. The Syft stage (`../05-sbom-syft`) uses it too, with the same arguments. |
| `helper/test_helper.py` | Its tests. `npm test` runs them in its image. |
| `helper/Dockerfile` | Its image: Python by digest. |

## What the stage sees and what leaves

- The stage sees only copies of the `pom.xml` files, not the code.
- OSV-Scanner stops on a SNAPSHOT version and asks nothing for it. So
  `osv_sarif.py` writes its own copies to `/tmp`, with no `-SNAPSHOT` at the
  end of a value: `3.2.0-SNAPSHOT` is resolved as `3.2.0`. The report keeps
  `3.2.0-SNAPSHOT` for an internal package.
- It is on a Docker network with no route out (`--internal`). It reaches
  only the helper, as its Maven registry: `http://proxy:8080/maven2`.
- The helper forwards only a `GET` of a `.pom` or `maven-metadata.xml`
  file to Maven Central, with no redirect. It refuses all the rest.
- For an internal package (`ch.vs.*`), the helper answers an empty POM and
  sends nothing out.
- The helper prints one line for each request. The runner counts them in
  the report and keeps them in the SARIF (`ci-scan/requests`).

The names of the public packages reach Maven Central. The build of the
project already asks Maven Central for the same packages.

## The internal packages

They are not checked here: they are checked in their own repository. The
report lists them "for information". The stage finds them in the answers
of OSV-Scanner and in the `pom.xml` files themselves, also in a profile.

## Limits

- OSV-Scanner does not resolve the dependencies of a Maven profile.
- Each scan asks for all the POM files again: about 700 for `bpesvc`, 50 s.
- A resolution that fails (a POM not found, a refused request) fails the
  stage: the scan blocks.
- A public SNAPSHOT dependency is checked at its release version. If this
  version is not on Maven Central yet, the stage fails: the scan blocks.
