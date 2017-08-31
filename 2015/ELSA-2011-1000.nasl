# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1000.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122121");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:25 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1000");
script_tag(name: "insight", value: "ELSA-2011-1000 -  rgmanager security, bug fix, and enhancement update - [2.0.52-21]- rgmanager: Fix bad passing of SFL_FAILURE up (fix_bad_passing_of_sfl_failure_up.patch) Resolves: rhbz#711521[2.0.52-20]- resource-agents: Improve LD_LIBRARY_PATH handling by SAP* (resource_agents_improve_ld_library_path_handling_by_sap*.patch) Resolves: rhbz#710637[2.0.52-19]- Fix changelog format- rgmanager: Fix reference count handling (fix_reference_count_handling.patch) Resolves: rhbz#692771[2.0.52-18]- resource-agents: postgres-8 resource agent does not detect a failed start of postgres server (postgres-8-Fix_pid_files.patch) Resolves: rhbz#663827[2.0.52-16]- rgmanager: Allow non-root clustat (allow_non_root_clustat.patch) Resolves: rhbz#510300- rgmanager: Initial commit of central proc + migration support (central_proc_+_migration_support.patch) Resolves: rhbz#525271- rgmanager: Make clufindhostname -i predictable (make_clufindhostname_i_predictable.patch) Resolves: rhbz#592613- resource-agents: Trim trailing slash for nfs clients (trim_trailing_slash_for_nfs_clients.patch) Resolves: rhbz#592624- rgmanager: Update last_owner on failover (update_last_owner_on_failover.patch) Resolves: rhbz#610483- rgmanager: Pause during exit if we stopped services (pause_during_exit_if_we_stopped_services.patch) Resolves: rhbz#619468- rgmanager: Fix quotaoff handling (fix_quotaoff_handling.patch) Resolves: rhbz#637678- resource-agents: Try force-unmount before fuser for netfs.sh (try_force_unmount_before_fuser_for_netfs_sh.patch) Resolves: rhbz#678494- rgmanager: Improve rgmanager's exclusive prioritization handling (improve_rgmanager_s_exclusive_prioritization_handling.patch) Resolves: rhbz#680256[2.0.52-15]- resource-agents: postgres-8 resource agent does not detect a failed start of postgres server (postgres-8-Do-not-send-TERM-signal-when-killing-post.patch) (postgres-8-Improve-testing-if-postgres-started-succe.patch) Resolves: rhbz#663827[2.0.52-14]- resource-agents: Fix problems when generating XML configuration file (rgmanager-Fix-problems-in-generated-XML-config-file.patch) Resolves: rhbz#637802[2.0.52-13]- resource-agents: Use literal quotes for tr calls (resource_agents_use_literal_quotes_for_tr_calls.patch) Resolves: rhbz#637154[2.0.52-12]- resource-agents: Use shutdown immediate in oracledb.sh (use_shutdown_immediate_in_oracledb_sh.patch) Resolves: rhbz#633992- rgmanager: Add path to rhev-check.sh (add_path_to_rhev_check_sh.patch) Resolves: rhbz#634225- rgmanager: Make clustat report correct version (make_clustat_report_correct_version.patch) Resolves: rhbz#654160[2.0.52-11]- resource-agents: Listen line in generated httpd.conf incorrect (resource-agents-Remove-netmask-from-IP-address-when.patch) Resolves: rhbz#675739- resource-agents: Disable updates to static routes by RHCS IP tooling (resource-agents-Add-option-disable_rdisc-to-ip.sh.patch) Resolves: rhbz#620700[2.0.52-10.1]- rgmanager: Fix nofailback when service is in 'starting' state (fix_nofailback_when_service_is_in_starting_state.patch) Resolves: rhbz#669440[2.0.52-10]- resource-agents: Problem with whitespace in mysql resource name (resource_agents_fix_whitespace_in_names.patch) Resolves: rhbz#632704"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1000");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1000.html");
script_cve_id("CVE-2010-3389");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"rgmanager", rpm:"rgmanager~2.0.52~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

