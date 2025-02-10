import { Controller, Get, Post, Body, Query, Res, Session } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  login(@Res() res: Response, @Session() session: any) {
    const authUrl = this.authService.getAuthorizationUrl(session);
    return res.redirect(authUrl);
  }


  @Get('callback')
  async callback(@Query('code') code: string, @Res() res: Response, @Session() session: any) {
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is missing' });
    }

    try {
      const tokenResponse = await this.authService.getAccessToken(code, session);
      this.authService.storeAccessToken(tokenResponse.access_token); // Save token
      return res.send('<h1>Login Successful!</h1><p>You can now access the protected resources.</p>');
    } catch (error) {
      console.error('Error during token exchange:', error);
      return res.status(500).json({ error: error.message });
    }
  }


  @Post('store-token')
  storeToken(@Body('access_token') token: string) {
    this.authService.storeAccessToken(token);
    return { message: 'Access token stored successfully' };
  }


  @Get('retrieve-token')
  getToken() {
    const token = this.authService.getStoredAccessToken();
    if (!token) {
      return { error: 'No access token found. Please login again.' };
    }
    return { access_token: token };
  }

@Get('get-hubs')
async getHubs(@Res() res: Response) {
  try {
    const hubs = await this.authService.getAutodeskHubs();
    return res.json(hubs);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
@Post('get-details')
async getDetails(
  @Body('hubId') hubId: string,
  @Res() res: Response,
) {
  if (!hubId) {
    return res.status(400).json({ error: 'Hub ID and Project ID are required' });
  }

  try {
    const details = await this.authService.getDetailsByHubAndProject(hubId);
    return res.json(details);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
@Post('get-issues')
async getissues(
  @Body('projectId') projectId: string,
  @Res() res: Response,
) {
  if (!projectId) {
    return res.status(400).json({ error: 'Hub ID and Project ID are required' });
  }

  try {
    const details = await this.authService.getissue(projectId);
    return res.json(details);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

@Post('get-folder')
async getfolder(
  @Body('hubId') hubId: string,
  @Body('projectId') projectId: string,

  @Res() res: Response,
) {
  if (!hubId) {
    return res.status(400).json({ error: 'Hub ID and Project ID are required' });
  }

  try {
    const details = await this.authService.getfolderId(hubId, projectId);
    return res.json(details);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

@Post('get-file')
async getfolderfile(
  @Body('projectId') projectId: string,
  @Body('folderId') folderId: string,

  @Res() res: Response,
) {
  if (!projectId) {
    return res.status(400).json({ error: 'Hub ID and Project ID are required' });
  }

  try {
    const details = await this.authService.getfolder1( projectId, folderId);
    return res.json(details);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

@Post('downloaf-file')
async getfile(
  @Body('fileId') fileId: string,

  @Res() res: Response,
) {
  if (!fileId) {
    return res.status(400).json({ error: 'Hub ID and Project ID are required' });
  }

  try {
    const details = await this.authService.downloadfile(fileId);
    return res.json(details);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

}
