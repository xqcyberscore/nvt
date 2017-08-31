# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0153.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123975");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:03 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0153");
script_tag(name: "insight", value: "ELSA-2012-0153 -  sos security, bug fix, and enhancement update - [1.7-9.62.0.1.el5]- add patch to remove all sysrq echo commands from sysreport.legacy (John Sobecki) [orabug 11061754]- comment out rh-upload-core and README.rh-upload-core in specfile[1.7-9.62]- Always log plugin exceptions that are not raised to the interpreter Resolves: bz717480- Ensure relative symlink targets are correctly handled when copying Resolves: bz717962- Correctly handle libxml2 parser exceptions when reading cluster.conf Resolves: bz750573- Update Red Hat Certificate System plugin for current versions Resolves: bz627416[1.7-9.61]- Make single threaded operation default and add --multithread to override Resolves: bz708346- Support multiple possible locations of VRTSexplorer script Resolves: bz565996- Collect wallaby dump and inventory information in mrggrid plugin Resolves: bz641020[1.7-9.60]- Add ethtool pause, coalesce and ring (-a, -c, -g) options to network plugin Resolves: bz726421- Update MRG grid plugin to collect additional logs and configuration Resolves: bz641020[1.7-9.59]- Fix collection of symlink destinations when copying directory trees Resolves: bz717962- Allow plugins to specify non-root symlinks for collected command output Resolves: bz716987- Ensure custom rsyslog destinations are captured and log size limits applied Resolves: bz717167[1.7-9.58]- Add basic plugin for Veritas products Resolves: bz565996- Do not collect subscription manager keys in general plugin Resolves: bz750606- Fix gfs2 plugin use of callExtProg API Resolves: bz667783[1.7-9.57]- Fix exceptions and file naming in gfs2 plugin Resolves: bz667783[1.7-9.56]- Fix translation for fr locale Resolves: bz641020[1.7-9.55]- Add basic Infiniband plugin Resolves: bz673246- Add plugin for scsi-target-utils iSCSI target Resolves: bz677123- Fix handling of TMP environment variable Resolves: bz733133- Correctly determine kernel version in cluster plugin Resolves: bz742567- Add libvirt plugin Resolves: bz568635- Add gfs2 plugin to supplement cluster data collection Resolves: bz667783"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0153");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0153.html");
script_cve_id("CVE-2011-4083");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~1.7~9.62.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

