###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_systemtap_mult_dos_vuln.nasl 9744 2018-05-07 11:41:23Z cfischer $
#
# SystemTap Unprivileged Mode Multiple Denial Of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
###############################################################################

tag_summary = "This host has SystemTap installed and is prone to multiple Denial of
  Service vulnerabilities.

  Vulnerabilities Insight:
  Multiple errors occur when SystemTap is running in 'unprivileged' mode.
  - Error within the handling of the unwind table and CIE/CFI records
  - A buffer overflow error when processing a long number of parameters
  - A stack overflow when processing DWARF information";

tag_solution = "Apply the patch from,
  https://bugzilla.redhat.com/attachment.cgi?id=365293
  https://bugzilla.redhat.com/attachment.cgi?id=365294
  https://bugzilla.redhat.com/attachment.cgi?id=365413

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Attackers can exploit this issue to execute arbitrary code and cause a denial
  of service or compromise a vulnerable system.
  Impact Level: System/Application.";
tag_affected = "SystemTap version 1.0 and prior.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901043");
  script_version("$Revision: 9744 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:41:23 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2911");
  script_bugtraq_id(36778);
  script_name("SystemTap Unprivileged Mode Multiple Denial Of Service Vulnerabilities");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2989");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=529175");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/10/21/1");
  script_xref(name : "URL" , value : "http://sources.redhat.com/bugzilla/show_bug.cgi?id=10750");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_require_keys("SystemTap/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

systapVer = get_kb_item("SystemTap/Ver");

if(systapVer != NULL)
{
  if(version_is_less_equal(version:systapVer, test_version:"1.0")){
    security_message(0);
  }
}
