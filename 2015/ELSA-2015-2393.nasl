# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2393.nasl 6600 2017-07-07 09:58:31Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.122747");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:22 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2393");
script_tag(name: "insight", value: "ELSA-2015-2393 -  wireshark security, bug fix, and enhancement update - [1.10.14-7.0.1]- Add oracle-ocfs2-network.patch to allow disassembly of OCFS2 interconnect[1.10.14-7]- Rebase some tvbuff API from upstream to 1.10.14- Fixes crash when tvb_length_remaining() is used- Related: CVE-2015-6244[1.10.14-6]- Security patch- Resolves: CVE-2015-3182[1.10.14-5]- Fix crash caused by -DGDK_PIXBUF_DEPRECATED on startup- Resolves: rhbz#1267959[1.10.14-4]- Security patches- Resolves: CVE-2015-6243 CVE-2015-6244 CVE-2015-6245 CVE-2015-6246 CVE-2015-6248[1.10.14-3]- Security patches- Resolves: CVE-2015-3810 CVE-2015-3813[1.10.14-2]- Add certificate verify message decoding in TLS extension- Resolves: #1239150[1.10.14-1]- Upgrade to 1.10.14- Resolves: #1238676[1.10.3-20]- add master secret extension decoding in TLS extension- add encrypt-then-mac extension decoding in TLS extension- Resolves: #1222901[1.10.3-19]- create pcap file if -F pcap specified- Resolves: #1227199[1.10.3-18]- add key exchange algorithms decoding in TLS extension- Resolves: #1222600[1.10.3-17]- add signature algorithms decoding in TLS extension- Resolves: #1221701[1.10.3-16]- add relro check- Resolves: #1092532[1.10.3-15]- add elliptic curves decoding in DTLS HELLO- Resolves: #1131202[1.10.3-14]- introduced nanosecond time precision- Resolves: #1213339[1.10.3-13]- security patches- Resolves: #1148267"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2393");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2393.html");
script_cve_id("CVE-2015-0563","CVE-2015-2188","CVE-2015-3182","CVE-2015-3810","CVE-2015-3811","CVE-2015-3812","CVE-2015-3813","CVE-2015-6243","CVE-2015-6244","CVE-2015-6245","CVE-2015-6246","CVE-2015-6248","CVE-2014-8710","CVE-2014-8711","CVE-2014-8712","CVE-2014-8713","CVE-2014-8714","CVE-2015-0562","CVE-2015-0564","CVE-2015-2189","CVE-2015-2191");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.14~7.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.10.14~7.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.10.14~7.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

