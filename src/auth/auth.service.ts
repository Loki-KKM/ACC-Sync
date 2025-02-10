import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { URLSearchParams } from 'url';
import axios from 'axios';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  private clientId: "HlgZAiBjHq7RbA9sI31HIxiBSUDHQCAg3re2A4NvHxZmb4CR";
  private redirectUri: "http://localhost:3000/auth/callback";
  private authUrl: string = 'https://developer.api.autodesk.com/authentication/v2/authorize';
  private tokenUrl: string = 'https://developer.api.autodesk.com/authentication/v2/token';
  private tokenStorage: Map<string, string> = new Map(); // Temporary storage


  constructor() {
  }


  generatePKCE(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = crypto.randomBytes(64).toString('hex');
    const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64');
    const codeChallenge = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // Base64 URL encoding
    return { codeVerifier, codeChallenge };
  }

  getAuthorizationUrl(session: any): string {
    const { codeVerifier, codeChallenge } = this.generatePKCE();
    session.codeVerifier = codeVerifier; // Store the code verifier in the session

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: "HlgZAiBjHq7RbA9sI31HIxiBSUDHQCAg3re2A4NvHxZmb4CR",
      redirect_uri: "http://localhost:3000/auth/callback",
      scope: 'viewables:read data:read data:write data:create data:search bucket:create bucket:read bucket:update bucket:delete',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: crypto.randomBytes(16).toString('hex'),
      prompt: 'login',
      nonce: crypto.randomBytes(16).toString('hex'),
    });
    return `${this.authUrl}?${params.toString()}`;
  }


  async getAccessToken(authCode: string, session: any): Promise<any> {
    const codeVerifier = session.codeVerifier; // Retrieve the stored code verifier

    if (!codeVerifier) {
      throw new Error('Code verifier missing in session');
    }

    const data = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: "HlgZAiBjHq7RbA9sI31HIxiBSUDHQCAg3re2A4NvHxZmb4CR",
      code: authCode,
      redirect_uri: "http://localhost:3000/auth/callback",
      code_verifier: codeVerifier,
    });

    try {
        const response = await axios.post(this.tokenUrl, data.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
  
        const accessToken = response.data.access_token;
        this.tokenStorage.set('access_token', accessToken); // Store in memory
        return response.data;
      } catch (error) {
        console.error('Error fetching access token:', error.response?.data || error.message);
        throw new Error('Failed to obtain access token');
      }
  }

  storeAccessToken(token: string): void {
    this.tokenStorage.set('access_token', token);
  }


  
  getStoredAccessToken(): string | null {
    return this.tokenStorage.get('access_token') || null;
  }
  async getAutodeskHubs(): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    try {
      const response = await axios.get('https://developer.api.autodesk.com/project/v1/hubs', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching hubs:', error.response?.data || error.message);
      throw new Error('Failed to fetch hubs');
    }
  }
  
  async getDetailsByHubAndProject(hubId: string): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    const url = `https://developer.api.autodesk.com/project/v1/hubs/${hubId}/projects`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching project details:', error.response?.data || error.message);
      throw new Error('Failed to fetch project details');
    }
  }
  async getfolderId(hubId: string, projectID: string): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    const url = `https://developer.api.autodesk.com/project/v1/hubs/${hubId}/projects/${projectID}/topFolders`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching project details:', error.response?.data || error.message);
      throw new Error('Failed to fetch project details');
    }
  }

  async getissue(projectID: string): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    const url = `https://developer.api.autodesk.com/construction/issues/v1/projects/${projectID}/issues`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching project details:', error.response?.data || error.message);
      throw new Error('Failed to fetch project details');
    }
  }

  async getfolder1(projectID: string, folderId: string): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    const url = `https://developer.api.autodesk.com/data/v1/projects/${projectID}/folders/${folderId}/contents`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching project details:', error.response?.data || error.message);
      throw new Error('Failed to fetch project details');
    }
  }

async downloadfile(fileId:string): Promise<any>{
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token found. Please login again.');
    }
  
    const url = `https://developer.api.autodesk.com/oss/v2/buckets/wip.dm.prod/objects/${fileId}/signeds3download`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
      });
  
      return response.data;
    } catch (error) {
      console.error('Error fetching project details:', error.response?.data || error.message);
      throw new Error('Failed to fetch project details');
    }

}

}
