###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_silc_prdts_channelname_format_string_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# SILC Client & Toolkit Channel Name Format String Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_solution = "Apply the patch or upgrade to SILC Toolkit 1.1.10.
  For updates refer to http://silcnet.org/

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****";

tag_impact = "Attackers can exploit this iisue to execute arbitrary code in the
  context of the affected application and compromise the system.
  Impact Level: Application/System";
tag_affected = "SILC Client 1.1.8 and prior
  SILC Toolkit prior to 1.1.10.";
tag_insight = "Multiple format string errors occur in 'lib/silcclient/command.c' while
  processing format string specifiers in the channel name field.";
tag_summary = "This host has SILC Client installed and is prone to Format
  String vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900958");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3163");
  script_bugtraq_id(36193);
  script_name("SILC Client Channel Name Format String Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36134");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/09/03/5");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_silc_prdts_detect.nasl");
  script_require_keys("SILC/Client/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# Check if the SILC-Client version is 1.1.8 or prior
clntVer = get_kb_item("SILC/Client/Ver");
if(clntVer)
{
  if(version_is_less_equal(version:clntVer, test_version:"1.1.8"))
  {
    security_message(0);
    exit(0);
  }
}
