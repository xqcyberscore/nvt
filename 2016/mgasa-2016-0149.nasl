# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0149.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.131300");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-05-09 14:18:03 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0149");
script_tag(name: "insight", value: "Updated java-1.8.0-openjdk packages fix security vulnerabilities: Multiple flaws were discovered in the Serialization and Hotspot components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions (CVE-2016-0686, CVE-2016-0687). It was discovered that the RMI server implementation in the JMX component in OpenJDK did not restrict which classes can be deserialized when deserializing authentication credentials. A remote, unauthenticated attacker able to connect to a JMX port could possibly use this flaw to trigger deserialization flaws (CVE-2016-3427). It was discovered that the JAXP component in OpenJDK failed to properly handle Unicode surrogate pairs used as part of the XML attribute values. Specially crafted XML input could cause a Java application to use an excessive amount of memory when parsed (CVE-2016-3425). It was discovered that the GCM (Galois/Counter Mode) implementation in the JCE component in OpenJDK used a non-constant time comparison when comparing GCM authentication tags. A remote attacker could possibly use this flaw to determine the value of the authentication tag (CVE-2016-3426). It was discovered that the Security component in OpenJDK failed to check the digest algorithm strength when generating DSA signatures. The use of a digest weaker than the key strength could lead to the generation of signatures that were weaker than expected (CVE-2016-0695)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0149.html");
script_cve_id("CVE-2016-0686","CVE-2016-0687","CVE-2016-0695","CVE-2016-3425","CVE-2016-3426","CVE-2016-3427");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0149");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
