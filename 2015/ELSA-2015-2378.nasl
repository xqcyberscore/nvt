# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2378.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122756");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:29 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2378");
script_tag(name: "insight", value: "ELSA-2015-2378 -  squid security and bug fix update - [7:3.3.8-26]- Related: #1186768 - removing patch, because of missing tests and incorrent patch[7:3.3.8-25]- Related: #1102842 - squid rpm package misses /var/run/squid needed for smp mode. Squid needs write access to /var/run/squid.[7:3.3.8-24]- Related: #1102842 - squid rpm package misses /var/run/squid needed for smp mode. Creation of /var/run/squid was also needed to be in SPEC file.[7:3.3.8-23]- Related: #1102842 - squid rpm package misses /var/run/squid needed for smp mode. Creation of this directory was moved to tmpfiles.d conf file.[7:3.3.8-22]- Related: #1102842 - squid rpm package misses /var/run/squid needed for smp mode. Creation of this directory was moved to service file.[7:3.3.8-21]- Resolves: #1263338 - squid with digest auth on big endian systems start looping[7:3.3.8-20]- Resolves: #1186768 - security issue: Nonce replay vulnerability in Digest authentication[7:3.3.8-19]- Resolves: #1225640 - squid crashes by segfault when it reboots[7:3.3.8-18]- Resolves: #1102842 - squid rpm package misses /var/run/squid needed for smp mode[7:3.3.8-17]- Resolves: #1233265 - CVE-2015-3455 squid: incorrect X509 server certificate validation[7:3.3.8-16]- Resolves: #1080042 - Supply a firewalld service file with squid[7:3.3.8-15]- Resolves: #1161600 - Squid does not serve cached responses with Vary headers[7:3.3.8-14]- Resolves: #1198778 - Filedescriptor leaks on snmp[7:3.3.8-13]- Resolves: #1204375 - squid sends incorrect ssl chain breaking newer gnutls using applications"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2378");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2378.html");
script_cve_id("CVE-2015-3455");
script_tag(name:"cvss_base", value:"2.6");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.3.8~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"squid-sysvinit", rpm:"squid-sysvinit~3.3.8~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

