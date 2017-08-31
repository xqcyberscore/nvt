# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2011-10.nasl 6579 2017-07-06 13:45:14Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.120500");
script_version("$Revision: 6579 $");
script_tag(name:"creation_date", value:"2015-09-08 11:27:06 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:45:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2011-10");
script_tag(name: "insight", value: "A flaw was found in the Java RMI (Remote Method Invocation) registry implementation. A remote RMI client could use this flaw to execute arbitrary code on the RMI server running the registry. (CVE-2011-3556 )A flaw was found in the Java RMI registry implementation. A remote RMI client could use this flaw to execute code on the RMI server with unrestricted privileges. (CVE-2011-3557 )A flaw was found in the IIOP (Internet Inter-Orb Protocol) deserialization code. An untrusted Java application or applet running in a sandbox could use this flaw to bypass sandbox restrictions by deserializing specially-crafted input. (CVE-2011-3521 )It was found that the Java ScriptingEngine did not properly restrict the privileges of sandboxed applications. An untrusted Java application or applet running in a sandbox could use this flaw to bypass sandbox restrictions. (CVE-2011-3544 )A flaw was found in the AWTKeyStroke implementation. An untrusted Java application or applet running in a sandbox could use this flaw to bypass sandbox restrictions. (CVE-2011-3548 )An integer overflow flaw, leading to a heap-based buffer overflow, was found in the Java2D code used to perform transformations of graphic shapes and images. An untrusted Java application or applet running in a sandbox could use this flaw to bypass sandbox restrictions. (CVE-2011-3551 )An insufficient error checking flaw was found in the unpacker for JAR files in pack200 format. A specially-crafted JAR file could use this flaw to crash the Java Virtual Machine (JVM) or, possibly, execute arbitrary code with JVM privileges. (CVE-2011-3554 )It was found that HttpsURLConnection did not perform SecurityManager checks in the setSSLSocketFactory method. An untrusted Java application or applet running in a sandbox could use this flaw to bypass connection restrictions defined in the policy. (CVE-2011-3560 )A flaw was found in the way the SSL 3 and TLS 1.0 protocols used block ciphers in cipher-block chaining (CBC) mode. An attacker able to perform a chosen plain text attack against a connection mixing trusted and untrusted data could use this flaw to recover portions of the trusted data sent over the connection. (CVE-2011-3389 )Note: This update mitigates the CVE-2011-3389  issue by splitting the first application data record byte to a separate SSL/TLS protocol record. This mitigation may cause compatibility issues with some SSL/TLS implementations and can be disabled using the jsse.enableCBCProtection boolean property. This can be done on the command line by appending the flag -Djsse.enableCBCProtection=false to the java command.An information leak flaw was found in the InputStream.skip implementation. An untrusted Java application or applet could possibly use this flaw to obtain bytes skipped by other threads. (CVE-2011-3547 )A flaw was found in the Java HotSpot virtual machine. An untrusted Java application or applet could use this flaw to disclose portions of the VM memory, or cause it to crash. (CVE-2011-3558 )The Java API for XML Web Services (JAX-WS) implementation in OpenJDK was configured to include the stack trace in error messages sent to clients. A remote client could possibly use this flaw to obtain sensitive information. (CVE-2011-3553 )It was found that Java applications running with SecurityManager restrictions were allowed to use too many UDP sockets by default. If multiple instances of a malicious application were started at the same time, they could exhaust all available UDP sockets on the system. (CVE-2011-3552 )"); 
script_tag(name : "solution", value : "Run yum update java-1.6.0-openjdk to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2011-10.html");
script_cve_id("CVE-2011-3521","CVE-2011-3554","CVE-2011-3556","CVE-2011-3548","CVE-2011-3551","CVE-2011-3552","CVE-2011-3553","CVE-2011-3389","CVE-2011-3547","CVE-2011-3558","CVE-2011-3560","CVE-2011-3544","CVE-2011-3557");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~52.1.9.10.40.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
