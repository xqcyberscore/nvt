# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0151.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131298");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-05-09 14:18:01 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0151");
script_tag(name: "insight", value: "Updated samba packages fix security vulnerability: Jouni Knuutinen discovered that Samba contained multiple flaws in the DCE/RPC implementation. A remote attacker could use this issue to perform a denial of service, downgrade secure connections by performing a man in the middle attack, or possibly execute arbitrary code (CVE-2015-5370). Stefan Metzmacher discovered that Samba contained multiple flaws in the NTLMSSP authentication implementation. A remote attacker could use this issue to downgrade connections to plain text by performing a man in the middle attack (CVE-2016-2110). Alberto Solino discovered that a Samba domain controller would establish a secure connection to a server with a spoofed computer name. A remote attacker could use this issue to obtain sensitive information (CVE-2016-2111). Stefan Metzmacher discovered that the Samba LDAP implementation did not enforce integrity protection. A remote attacker could use this issue to hijack LDAP connections by performing a man in the middle attack (CVE-2016-2112). Stefan Metzmacher discovered that Samba did not enable integrity protection for IPC traffic. A remote attacker could use this issue to perform a man in the middle attack (CVE-2016-2115). Stefan Metzmacher discovered that Samba incorrectly handled the MS-SAMR and MS-LSAD protocols. A remote attacker could use this flaw with a man in the middle attack to impersonate users and obtain sensitive information from the Security Account Manager database. This flaw is known as Badlock (CVE-2016-2118)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0151.html");
script_cve_id("CVE-2015-5370","CVE-2016-2110","CVE-2016-2111","CVE-2016-2112","CVE-2016-2115","CVE-2016-2118");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0151");
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
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.25~2.3.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
