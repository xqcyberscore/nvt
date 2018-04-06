###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mssql_sp_replwritetovarbin_bof_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Microsoft SQL Server sp_replwritetovarbin() BOF Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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

tag_impact = "Successful exploitation could result in heap based buffer overflow via
  specially crafted arguments passed to the affected application.
  Impact Level: Application";
tag_affected = "Microsoft SQL Server 2000 and 2005 on Windows.";
tag_insight = "The flaw is due to a boundary error in the implementation of the
  function sp_replwritetovarbin() SQL procedure.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-004.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-004.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800082");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5416");
  script_bugtraq_id(32710);
  script_name("Microsoft SQL Server sp_replwritetovarbin() BOF Vulnerability");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Dec/1021363.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/961040.mspx");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-004.mspx");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/499042/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.sec-consult.com/files/20081209_mssql-2000-sp_replwritetovarbin_memwrite.txt");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl", "mssql_version.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(1433, "Services/mssql", 139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

mssqlPort = get_kb_item("Services/mssql");
if(!mssqlPort){
  mssqlPort = 1433;
}

if(!get_port_state(mssqlPort)){
  exit(0);
}

function Get_FileVersion(ver, path)
{
  if(ver == "MS SQL Server 2005")
  {
    item = "SQLBinRoot";
    file = "\sqlservr.exe";
  }

  if(ver == "MS SQL Server 2000")
  {
    item = "InstallLocation";
    file = "\Binn\sqlservr.exe";
  }

  sqlFile = registry_get_sz(key:path ,item:item);
  if(!sqlFile){
    exit(0);
  }

  sqlFile += file;
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:sqlFile);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:sqlFile);

  fileVer = GetVer(file:file, share:share);
  if(!fileVer){
    return 0;
  }
  else return fileVer;
}


# Retrieving Microsoft SQL Server 2005 Registry entry
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                           "\Uninstall\Microsoft SQL Server 2005")){
  msSqlSer = "MS SQL Server 2005";
}
# Retrieving Microsoft SQL Server 2000 Registry entry
else if (registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\Microsoft SQL Server 2000")){
  msSqlSer = "MS SQL Server 2000";
}

if(!msSqlSer){
  exit(0);
}

if(msSqlSer == "MS SQL Server 2005")
{
  reqSqlVer = "2005.90.3077.0";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft" +
                                "\Microsoft SQL Server\MSSQL.1\Setup");
}
else if(msSqlSer == "MS SQL Server 2000")
{
  reqSqlVer = "2000.80.2055.0";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Windows" +
                        "\CurrentVersion\Uninstall\Microsoft SQL Server 2000");
}

if(!insSqlVer){
  exit(0);
}

if(version_is_less(version:insSqlVer, test_version:reqSqlVer)){
  security_message(mssqlPort);
}
