###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for hostapd MDVSA-2012:168 (hostapd)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities has been discovered and corrected in hostapd:

  hostapd 0.7.3, and possibly other versions before 1.0, uses 0644
  permissions for /etc/hostapd/hostapd.conf, which might allow
  local users to obtain sensitive information such as credentials
  (CVE-2012-2389).

  Heap-based buffer overflow in the eap_server_tls_process_fragment
  function in eap_server_tls_common.c in the EAP authentication server
  in hostapd 0.6 through 1.0 allows remote attackers to cause a denial
  of service (crash or abort) via a small TLS Message Length value in
  an EAP-TLS message with the More Fragments flag set (CVE-2012-4445).

  The updated packages have been patched to correct these issues.";

tag_affected = "hostapd on Mandriva Linux 2011.0";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:168");
  script_id(831748);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-10-23 09:29:43 +0530 (Tue, 23 Oct 2012)");
  script_cve_id("CVE-2012-2389", "CVE-2012-4445");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDVSA", value: "2012:168");
  script_name("Mandriva Update for hostapd MDVSA-2012:168 (hostapd)");

  script_tag(name: "summary" , value: "Check for the Version of hostapd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~0.7.3~2.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
