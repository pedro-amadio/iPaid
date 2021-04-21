import { Injectable } from '@angular/core';
import {
    HttpRequest,
    HttpHandler,
    HttpEvent,
    HttpInterceptor, HttpResponse, HttpErrorResponse
} from '@angular/common/http';
import { Observable } from 'rxjs';
import {SessionManagerService} from '../services/session-manager.service';
import {map, tap} from 'rxjs/operators';
import {UserSession} from '../models/user-session';
import {environment} from '../../environments/environment';
import * as jwt from "jsonwebtoken";
import moment from "moment";
import { EMPTY } from 'rxjs';
import {AuthService} from '../providers/auth/auth.service';
import {IncomingMessage} from "http";

@Injectable()
export class TokenInterceptor implements HttpInterceptor {
    constructor(public sessionManager: SessionManagerService, public authService: AuthService) {}

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        request = request.clone({
            setHeaders: {
                csrfmiddlewaretoken : `${this.sessionManager.session ? this.sessionManager.session.token : 'none'}`,
            }
        });
        if (!request.url.includes(navigator.language+'.json') && (!request.headers.has('Permission') || !this.authService.validate(request.headers.get('Permission')) ) ){
            return EMPTY;
        }
        return next.handle(request).pipe(
            tap(
                (err: any) => {

                    if (err instanceof HttpResponse) {
                        if(err.headers.has('csrfmiddlewaretoken')) {
                            const token = err.headers.get('csrfmiddlewaretoken');
                            const parsedToken = jwt.verify(token,environment.SECRET, { algorithm: 'HS256'});
                            let sessionAux = this.sessionManager.session;
                            let session:UserSession = new UserSession();
                            session.browser_fingerprint = sessionAux.browser_fingerprint;
                            session.token = token;
                            this.sessionManager.save(session);
                        }
                    }
                }
            )
        );
    }
}
