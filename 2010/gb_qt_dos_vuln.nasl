###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qt_dos_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# Qt 'QSslSocketBackendPrivate::transmit()' Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801235");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41250);
  script_cve_id("CVE-2010-2621");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Qt 'QSslSocketBackendPrivate::transmit()' Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40389");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/qtsslame-adv.txt");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1657");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_qt_detect.nasl");
  script_mandatory_keys("Qt/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of
service.");
  script_tag(name:"affected", value:"Qt Version 4.6.3 and prior.");
  script_tag(name:"insight", value:"This flaw is due to an endless loop within the
'QSslSocketBackendPrivate::transmit()' function in
'src/network/ssl/qsslsocket_openssl.cpp'. This can be exploited to
exhaust CPU resources in server applications using the QSslSocket class.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 4.6.4 or later,
For updates refer to ftp://ftp.qt.nokia.com/qt/source");
  script_tag(name:"summary", value:"This host is installed with Qt and is prone to denial of service
vulnerability.");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("Qt/Ver");

if(ver != NULL)
{
  if(version_is_less_equal(version:ver, test_version:"4.6.3") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
