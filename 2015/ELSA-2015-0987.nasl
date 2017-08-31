# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0987.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123122");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:37 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0987");
script_tag(name: "insight", value: "ELSA-2015-0987 -  kernel security and bug fix update - [3.10.0-229.4.2]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-229.4.2]- [x86] crypto: aesni - fix memory usage in GCM decryption (Kurt Stutsman) [1213331 1212178] {CVE-2015-3331}[3.10.0-229.4.1]- [crypto] x86: sha256_ssse3 - also test for BMI2 (Herbert Xu) [1211484 1201563]- [crypto] testmgr: fix RNG return code enforcement (Herbert Xu) [1211487 1198978]- [crypto] rng: RNGs must return 0 in success case (Herbert Xu) [1211487 1198978]- [crypto] x86: sha1 - reduce size of the AVX2 asm implementation (Herbert Xu) [1211291 1177968]- [crypto] x86: sha1 - fix stack alignment of AVX2 variant (Herbert Xu) [1211291 1177968]- [crypto] x86: sha1 - re-enable the AVX variant (Herbert Xu) [1211291 1177968]- [crypto] sha: SHA1 transform x86_64 AVX2 (Herbert Xu) [1211291 1177968]- [crypto] sha-mb: sha1_mb_alg_state can be static (Herbert Xu) [1211290 1173756]- [crypto] mcryptd: mcryptd_flist can be static (Herbert Xu) [1211290 1173756]- [crypto] sha-mb: SHA1 multibuffer job manager and glue code (Herbert Xu) [1211290 1173756]- [crypto] sha-mb: SHA1 multibuffer crypto computation (x8 AVX2) (Herbert Xu) [1211290 1173756]- [crypto] sha-mb: SHA1 multibuffer submit and flush routines for AVX2 (Herbert Xu) [1211290 1173756]- [crypto] sha-mb: SHA1 multibuffer algorithm data structures (Herbert Xu) [1211290 1173756]- [crypto] sha-mb: multibuffer crypto infrastructure (Herbert Xu) [1211290 1173756]- [kernel] sched: Add function single_task_running to let a task check if it is the only task running on a cpu (Herbert Xu) [1211290 1173756]- [crypto] ahash: initialize entry len for null input in crypto hash sg list walk (Herbert Xu) [1211290 1173756]- [crypto] ahash: Add real ahash walk interface (Herbert Xu) [1211290 1173756]- [char] random: account for entropy loss due to overwrites (Herbert Xu) [1211288 1110044]- [char] random: allow fractional bits to be tracked (Herbert Xu) [1211288 1110044]- [char] random: statically compute poolbitshift, poolbytes, poolbits (Herbert Xu) [1211288 1110044][3.10.0-229.3.1]- [netdrv] mlx4_en: tx_info->ts_requested was not cleared (Doug Ledford) [1209240 1178070][3.10.0-229.2.1]- [char] tpm: Added Little Endian support to vtpm module (Steve Best) [1207051 1189017]- [powerpc] pseries: Fix endian problems with LE migration (Steve Best) [1207050 1183198]- [iommu] vt-d: Work around broken RMRR firmware entries (Myron Stowe) [1205303 1195802]- [iommu] vt-d: Store bus information in RMRR PCI device path (Myron Stowe) [1205303 1195802]- [s390] zcrypt: enable s390 hwrng to seed kernel entropy (Hendrik Brueckner) [1205300 1196398]- [s390] zcrypt: improve device probing for zcrypt adapter cards (Hendrik Brueckner) [1205300 1196398]- [net] team: fix possible null pointer dereference in team_handle_frame (Jiri Pirko) [1202359 1188496]- [fs] fsnotify: fix handling of renames in audit (Paul Moore) [1202358 1191562]- [net] openvswitch: Fix net exit (Jiri Benc) [1202357 1200859]- [fs] gfs2: Move gfs2_file_splice_write outside of #ifdef (Robert S Peterson) [1201256 1193910]- [fs] gfs2: Allocate reservation during splice_write (Robert S Peterson) [1201256 1193910]- [crypto] aesni: fix 'by8' variant for 128 bit keys (Herbert Xu) [1201254 1174971]- [crypto] aesni: remove unused defines in 'by8' variant (Herbert Xu) [1201254 1174971]- [crypto] aesni: fix counter overflow handling in 'by8' variant (Herbert Xu) [1201254 1174971]- [crypto] aes: AES CTR x86_64 'by8' AVX optimization (Herbert Xu) [1201254 1174971]- [kernel] audit: restore AUDIT_LOGINUID unset ABI (Richard Guy Briggs) [1197748 1120491]- [kernel] audit: replace getname()/putname() hacks with reference counters (Paul Moore) [1197746 1155208]- [kernel] audit: fix filename matching in __audit_inode() and __audit_inode_child() (Paul Moore) [1197746 1155208]- [kernel] audit: enable filename recording via getname_kernel() (Paul Moore) [1197746 1155208]- [fs] namei: simpler calling conventions for filename_mountpoint() (Paul Moore) [1197746 1155208]- [fs] namei: create proper filename objects using getname_kernel() (Paul Moore) [1197746 1155208]- [fs] namei: rework getname_kernel to handle up to PATH_MAX sized filenames (Paul Moore) [1197746 1155208]- [fs] namei: cut down the number of do_path_lookup() callers (Paul Moore) [1197746 1155208]- [fs] execve: use 'struct filename *' for executable name passing (Paul Moore) [1197746 1155208]- [infiniband] core: Prevent integer overflow in ib_umem_get address arithmetic (Doug Ledford) [1181177 1179347] {CVE-2014-8159}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0987");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0987.html");
script_cve_id("CVE-2015-3331");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

