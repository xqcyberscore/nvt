###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_taskmgr_info_disc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# MS Windows taskmgr.exe Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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

tag_impact = "Successful exploitation will let the attacker retrieve password related
  information and can cause brute force or benchmarking attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP SP3 and prior.
  Microsoft Windows Server 2003 SP2 and prior.";
tag_insight = "The I/O activity measurement of all processes allow to obtain sensitive
  information by reading the I/O other bytes column in taskmgr.exe to
  estimate the number of characters that a different user entered at a
  password prompt through 'runas.exe'.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "This host is running Windows Operating System and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900302");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0320");
  script_bugtraq_id(33440);
  script_name("MS Windows taskmgr.exe Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.unifiedds.com/?p=44");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500393/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("secpod_reg.inc");

exit(0); ## plugin may results to FP

if(hotfix_check_sp(xp:4, win2003:3) > 0){
  security_message(0);
}
