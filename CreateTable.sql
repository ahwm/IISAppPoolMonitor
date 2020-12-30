CREATE TABLE AppStatus (
	Id int NOT NULL IDENTITY(1,1) CONSTRAINT PK_APPSTATUS PRIMARY KEY,
	AppName varchar(100) NOT NULL,
	DateStarted datetime NOT NULL CONSTRAINT DF_APPSTATUS_DATESTARTED DEFAULT GETDATE(),
	ServerName varchar(50) NOT NULL
)