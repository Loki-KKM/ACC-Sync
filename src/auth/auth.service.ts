import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { URLSearchParams } from 'url';
import axios from 'axios';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

interface UploadSession {
  projectId: string;
  folderId: string;
  fileName: string;
  objectName: string;
  signedUrl: string;
  uploadKey: string;
}


@Injectable()
export class AuthService {
  private authUrl: string = 'https://developer.api.autodesk.com/authentication/v2/authorize';
  private tokenUrl: string = 'https://developer.api.autodesk.com/authentication/v2/token';
  private tokenStorage: Map<string, string> = new Map(); 

  private sessions: Map<string, UploadSession> = new Map();

  private readonly BIM_BUCKET = 'wip.dm.prod';

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
      client_id: process.env.client_id,
      redirect_uri: process.env.redirect_uri,
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
      client_id: process.env.client_id,
      code: authCode,
      redirect_uri: process.env.redirect_uri,
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

  async addIssues(projectID: string, requestBody: any): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
      throw new Error('No access token provided');
    }

    const url = `https://developer.api.autodesk.com/construction/issues/v1/projects/${projectID}/issues`;

    try {
      const response = await axios.post(url, requestBody, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data || 'Error creating issue');
    }
  }
  async getsubmittal(projectID: string): Promise<any> {
    const accessToken = this.getStoredAccessToken();
    if (!accessToken) {
        throw new Error('No access token found. Please login again.');
    }

    const url = `https://developer.api.autodesk.com/construction/submittals/v2/projects/${projectID}/items`;

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
async addSubmittal(projectID: string, requestBody: any): Promise<any> {
  const accessToken = this.getStoredAccessToken();
  if (!accessToken) {
    throw new Error('No access token provided');
  }

  const url = `https://developer.api.autodesk.com/construction/submittals/v2/projects/${projectID}/items`;

  try {
    const response = await axios.post(url, requestBody, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    throw new Error(error.response?.data || 'Error creating issue');
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
async initUpload(fileName: string, projectId: string, folderId: string): Promise<{ sessionId: string }> {
  const accessToken = this.getStoredAccessToken();
  // Step 1: Create Storage Object
  const storageUrl = `https://developer.api.autodesk.com/data/v1/projects/${projectId}/storage`;
  const storageBody = {
    jsonapi: { version: '1.0' },
    data: {
      type: 'objects',
      attributes: { name: fileName },
      relationships: {
        target: {
          data: {
            type: 'folders',
            id: folderId
          }
        }
      }
    }
  };

  let storageResponse;
  try {
    storageResponse = await axios.post(storageUrl, storageBody, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/vnd.api+json',
        'Accept': 'application/vnd.api+json'
      }
    });
  } catch (error) {
    throw new HttpException(
      error.response?.data || 'Failed to create storage object',
      error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  // Extract objectName from storageResponse.data.data.id
  // Example: "urn:adsk.objects:os.object:wip.dm.prod/64ab8d24-e985-4c48-8c8b-ac7f868c619d.rvt"
  const fullObjectId: string = storageResponse.data.data.id;
  const parts = fullObjectId.split('/');
  if (parts.length < 2) {
    throw new HttpException('Invalid object id returned', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  const objectName = parts[parts.length - 1];

  // Step 2: Get Signed S3 Upload URL
  const signedUrlEndpoint = `https://developer.api.autodesk.com/oss/v2/buckets/${this.BIM_BUCKET}/objects/${objectName}/signeds3upload`;
  let signedResponse;
  try {
    signedResponse = await axios.get(signedUrlEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      }
    });
  } catch (error) {
    throw new HttpException(
      error.response?.data || 'Failed to get signed S3 upload URL',
      error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  // Assume the response contains "urls" and "uploadKey"
  const { urls, uploadKey } = signedResponse.data;
  if (!urls || !uploadKey) {
    throw new HttpException('Signed URL response is missing required fields', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  // We take the first URL from the urls array
  const signedUrl = urls[0];

  // Create an upload session id to tie this process together.
  const sessionId = uuidv4();
  this.sessions.set(sessionId, {
    projectId,
    folderId,
    fileName,
    objectName,
    signedUrl,
    uploadKey
  });

  return { sessionId };
}

/**
 * Step 2: Upload file (binary) and finalize the process.
 */
async uploadFile(sessionId: string, fileBuffer: Buffer): Promise<any> {
  const accessToken = this.getStoredAccessToken();
  const session = this.sessions.get(sessionId);
  if (!session) {
    throw new HttpException('Upload session not found', HttpStatus.BAD_REQUEST);
  }
  const { projectId, folderId, fileName, objectName, signedUrl, uploadKey } = session;

  // Step 3: Upload the binary file with PUT to the signed URL.
  try {
    const putResponse = await axios.put(signedUrl, fileBuffer, {
      // In case you want to see the status code etc.
      validateStatus: (status) => status < 500,
    });
    if (putResponse.status !== 200) {
      throw new Error(`PUT upload failed with status ${putResponse.status}`);
    }
  } catch (error) {
    throw new HttpException(
      error.message || 'Failed to upload file',
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  // Step 4: Finalize S3 upload
  const finalizeUrl = `https://developer.api.autodesk.com/oss/v2/buckets/${this.BIM_BUCKET}/objects/${objectName}/signeds3upload`;
  try {
    const finalizeResponse = await axios.post(finalizeUrl, { uploadKey }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    if (finalizeResponse.status !== 200) {
      throw new Error(`Finalize upload failed with status ${finalizeResponse.status}`);
    }
  } catch (error) {
    throw new HttpException(
      error.message || 'Failed to finalize file upload',
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  // Step 5: Create the BIM360 Item (version and item creation)
  const createItemUrl = `https://developer.api.autodesk.com/data/v1/projects/${projectId}/items`;
  // Build the storage URN using the full object id format.
  const storageUrn = `urn:adsk.objects:os.object:${this.BIM_BUCKET}/${objectName}`;

  const createItemBody = {
    jsonapi: { version: '1.0' },
    data: {
      type: 'items',
      attributes: {
        displayName: fileName,
        extension: {
          type: 'items:autodesk.bim360:File',
          version: '1.0'
        }
      },
      relationships: {
        tip: {
          data: {
            type: 'versions',
            id: '1'
          }
        },
        parent: {
          data: {
            type: 'folders',
            id: folderId
          }
        }
      }
    },
    included: [
      {
        type: 'versions',
        id: '1',
        attributes: {
          name: fileName,
          extension: {
            type: 'versions:autodesk.bim360:File',
            version: '1.0'
          }
        },
        relationships: {
          storage: {
            data: {
              type: 'objects',
              id: storageUrn
            }
          }
        }
      }
    ]
  };

  let createItemResponse;
  try {
    createItemResponse = await axios.post(createItemUrl, createItemBody, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/vnd.api+json',
        Accept: 'application/vnd.api+json'
      }
    });
    if (createItemResponse.status !== 201) {
      throw new Error(`Create item failed with status ${createItemResponse.status}`);
    }
  } catch (error) {
    throw new HttpException(
      error.response?.data || error.message || 'Failed to create item',
      error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  // Optionally clear the session as it's completed.
  this.sessions.delete(sessionId);

  // Return the created item response (or any success message)
  return createItemResponse.data;
}

async getIssueType(projectID: string): Promise<any> {
  const accessToken = this.getStoredAccessToken();
  if (!accessToken) {
    throw new Error('No access token provided');
  }

  const url = `https://developer.api.autodesk.com/construction/issues/v1/projects/${projectID}/issue-types`;

  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
      params: {
        include: 'subtypes', // Properly setting the parameter
      },
    });

    return response.data;
  } catch (error) {
    console.error('Error fetching issue types:', error.response?.data || error.message);
    throw new Error('Failed to fetch issue types');
  }
}

}
