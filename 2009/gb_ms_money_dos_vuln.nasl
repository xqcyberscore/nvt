###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_money_dos_vuln.nasl 4918 2017-01-02 14:56:10Z cfi $
#
# Microsoft Money 'prtstb06.dll' Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to change the vulnerable
  EIP value and can cause denial of service to the application.
  Impact Level: Application";
tag_affected = "Microsoft Money 2006 on Windows.";
tag_insight = "The flaw is due to an error in the Windows Based Script Host which lets
  the attacker execute arbitrary codes in the vulnerable buffer to crash
  the application.";
tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided
  anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.
  For updates refer to http://www.microsoft.com/MONEY/default.mspx";
tag_summary = "This host has Microsoft Money installed and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(800218);
  script_version("$Revision: 4918 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 15:56:10 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5823");
  script_name("Microsoft Money 'prtstb06.dll' Denial of Service vulnerability");
  script_xref(name : "URL" , value : "http://jbrownsec.blogspot.com/2008/12/new-year-research-are-upon-us.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_money_detect.nasl");
  script_mandatory_keys("MS/Money/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


msmVer = get_kb_item("MS/Money/Version");
if(!msmVer){
  exit(0);
}

# Check for version Microsoft Money 2006
if(msmVer =~ "2006"){
  security_message(0);
}
