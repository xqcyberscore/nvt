# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0509.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123718");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:37 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0509");
script_tag(name: "insight", value: "ELSA-2013-0509 -  rdma security, bug fix and enhancement update - ibacm[1.0.8-0.git7a3adb7]- Update to latest upstream via git repo- Resolves: bz866222, bz866223ibsim[0.5-7]- Bump and rebuild against latest opensm- Related: bz756396ibutils[1.5.7-7]- Bump and rebuild against latest opensm- Related: bz756396infiniband-diags[1.5.12-5]- Bump and rebuild against latest opensm- Pick up fixes done for rhel5.9- Related: bz756396[1.5.12-4]- Update the all_hcas patch to resolve several problems- Give a simple help message to the ibnodes script- Resolves: bz818606, bz847129infinipath-psm[3.0.1-115.1015_open.1]- New upstream releas Resolves: rhbz818789libibmad[1.3.9-1]- Update to latest upstream version (more SRIOV support)- Related: bz756396[1.3.8-1]- Update to latest upstream version (for FDR link speed support)- Related: bz750609[1.3.7-1]- Update to latest upstream version (1.3.4 -> 1.3.7)- Related: bz725016[1.3.4-1]- New upstream version[1.3.3-2]- ExcludeArch s390(x) as there's no hardware support there[1.3.3-1]- Update to latest upstream release[1.3.2-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild[1.3.2-1]- Update to latest upstream version- Require the same version of libibumad as our version[1.3.1-1]- Update to latest upstream version[1.2.0-3]- Rebuilt against libtool 2.2[1.2.0-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild[1.2.0-1]- Initial package for Fedora review processlibibumad[1.3.8-1]- Update to latest upstream release (more SRIOV support)- Related: bz756396[1.3.7-1]- Update to latest upstream version (1.3.4 -> 1.3.7)- Related: bz725016[1.3.4-1]- New upstream release[1.3.3-2]- ExcludeArch s390(x) as there is no hardware support there[1.3.3-1]- Update to latest upstream version[1.3.2-3]- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild[1.3.2-2]- Forgot to remove both instances of the libibcommon requires- Add build requires on glibc-static[1.3.2-1]- Update to latest upstream version- Remove requirement on libibcommon since that library is no longer needed- Fix a problem with man page listing[1.3.1-1]- Update to latest upstream version[1.2.0-3]- Rebuilt against libtool 2.2[1.2.0-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild[1.2.0-1]- Initial package for Fedora review processlibibverbs[1.1.6-5]- Don't print link state on iWARP links as it's always invalid- Don't try to do ud transfers in excess of port MTU- Resolves: bz822781libmlx4[1.0.4-1]- Update to latest upstream version- Related: bz756396librdmacm[1.0.17-0.git4b5c1aa]- Pre-release version of 1.0.17- Resolves a CVE vulnerability between librdmacm and ibacm- Fixes various minor bugs in sample programs- Resolves: bz866221, bz816074opensm[3.3.15-1]- Update to latest upstream source (adds more SRIOV support)- Fix init script when no config files are present- Related: bz756396[3.3.13-1]- Update to latest upstream release- Add patch to support specifying subnet_prefix on command lien- Update init script to pass unique subnet_prefix's when using the GUID method of starting multiple instances- Fix up LSB init script headers- Resolves: bz754196[3.3.12-1]- Generate the opensm.conf file instead of shipping a static one as a source- Update to latest upstream release (FDR link speed support)- Resolves: bz750609[3.3.9-1]- Update to latest upstream version (3.3.5 -> 3.3.9)- Add /etc/sysconfig/opensm for use by opensm init script- Enable the ability to start more than one instance of opensm for multiple fabric support- Enable the ability to start opensm with a priority other than default for support of backup opensm instances- Related: bz725016- Resolves: bz633392[3.3.5-1]- Update to latest upstream release. We need various defines in ib_types.h for the latest ibutils package to build properly, and the latest ibutils package is needed because we found licensing problems in the older tarballs during review.[3.3.3-2]- ExcludeArch s390(x) as there's no hardware support there[3.3.3-1]- Update to latest upstream release- Minor tweaks to init script for LSB compliance[3.3.2-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild[3.3.2-1]- Update to latest upstream version[3.3.1-1]- Update to latest upstream version[3.2.1-3]- fix bare elifs to rebuild[3.2.1-2]- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild[3.2.1-1]- Initial package for Fedora review processrdma[3.6-1.0.2]- Add SDP to rdma.conf and rdma.init[3.6-1.0.1]- Support Mellanox OFED 1.5.5[3.6-1]- Bump version to match final kernel submission[3.6-0.rc5.1]- Bump version to match kernel update submitted for rhel6.4"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0509");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0509.html");
script_cve_id("CVE-2012-4517","CVE-2012-4518");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"ibacm", rpm:"ibacm~1.0.8~0.git7a3adb7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ibacm-devel", rpm:"ibacm-devel~1.0.8~0.git7a3adb7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ibsim", rpm:"ibsim~0.5~7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.5.7~7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ibutils-devel", rpm:"ibutils-devel~1.5.7~7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.5.7~7.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"infiniband-diags", rpm:"infiniband-diags~1.5.12~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"infiniband-diags-devel", rpm:"infiniband-diags-devel~1.5.12~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"infiniband-diags-devel-static", rpm:"infiniband-diags-devel-static~1.5.12~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibmad", rpm:"libibmad~1.3.9~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibmad-devel", rpm:"libibmad-devel~1.3.9~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibmad-static", rpm:"libibmad-static~1.3.9~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibumad", rpm:"libibumad~1.3.8~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibumad-devel", rpm:"libibumad-devel~1.3.8~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibumad-static", rpm:"libibumad-static~1.3.8~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibverbs", rpm:"libibverbs~1.1.6~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibverbs-devel", rpm:"libibverbs-devel~1.1.6~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibverbs-devel-static", rpm:"libibverbs-devel-static~1.1.6~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libibverbs-utils", rpm:"libibverbs-utils~1.1.6~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libmlx4", rpm:"libmlx4~1.0.4~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libmlx4-static", rpm:"libmlx4-static~1.0.4~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"librdmacm", rpm:"librdmacm~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"librdmacm-devel", rpm:"librdmacm-devel~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"librdmacm-static", rpm:"librdmacm-static~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"librdmacm-utils", rpm:"librdmacm-utils~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"opensm", rpm:"opensm~3.3.15~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"opensm-devel", rpm:"opensm-devel~3.3.15~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"opensm-libs", rpm:"opensm-libs~3.3.15~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"opensm-static", rpm:"opensm-static~3.3.15~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rdma", rpm:"rdma~3.6~1.0.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"infinipath-psm", rpm:"infinipath-psm~3.0.1~115.1015_open.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"infinipath-psm-devel", rpm:"infinipath-psm-devel~3.0.1~115.1015_open.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

