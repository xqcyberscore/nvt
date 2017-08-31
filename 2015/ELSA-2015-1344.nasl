# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1344.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123055");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:46 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1344");
script_tag(name: "insight", value: "ELSA-2015-1344 -  autofs security and bug fix update - [5.0.5-113.0.1]- add autofs-5.0.5-lookup-mounts.patch [Orabug:12658280] (Bert Barbe) use tcp instead of udp[5.0.5-113]- bz1201195 - autofs: MAPFMT_DEFAULT is not macro in lookup_program.c - fix macro usage in lookup_program.c.- Resolves: rhbz#1201195[5.0.5-112]- bz1124083 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate exports in the NFS server - fix use after free in patch to handle duplicate in multi mounts. - change log messages to try and make them more sensible.- fix log entry for rev 5.0.5-111 below.- Related: rhbz#1124083[5.0.5-111]- bz1153130 - autofs-5.0.5-109 with upgrade to RHEL 6.6 no longer recognizes +yp: in auto.master - fix fix master map type check.- bz1156387 - autofs /net maps do not refresh list of shares exported on the NFS server - fix typo in update_hosts_mounts(). - fix hosts map update on reload.- bz1160446 - priv escalation via interpreter load path for program based automount maps - add a prefix to program map stdvars. - add config option to force use of program map stdvars.- bz1175671 - automount segment fault in parse_sun.so for negative parser tests - fix incorrect check in parse_mount().- bz1124083 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate exports in the NFS server - fix fix map entry duplicate offset detection (dependednt patch). - handle duplicates in multi mounts.- Resolves: rhbz#1153130 rhbz#1156387 rhbz#1160446 rhbz#1175671 rhbz#1124083[5.0.5-110]- bz1163957 - Autofs unable to mount indirect after attempt to mount wildcard - make negative cache update consistent for all lookup modules. - ensure negative cache isn't updated on remount. - dont add wildcard to negative cache.- Resolves: rhbz#1163957"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1344");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1344.html");
script_cve_id("CVE-2014-8169");
script_tag(name:"cvss_base", value:"4.4");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.5~113.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

